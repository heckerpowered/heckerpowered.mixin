#include "module_map.hpp"

namespace module{
	namespace map {
		NTSTATUS resolve_api_set(PEPROCESS process, const UNICODE_STRING& name, const UNICODE_STRING& base_image, UNICODE_STRING& resolved) noexcept {
			auto peb32{ reinterpret_cast<PPEB32>(PsGetProcessWow64Process(process)) };
			auto peb{ PsGetProcessPeb(process) };
			auto api_set_map{ reinterpret_cast<PAPISET_NAMESPACE_ARRAY>(peb32 ? reinterpret_cast<void*>(peb32->ApiSetMap) : peb->ApiSetMap) };

			if (name.Buffer == nullptr || name.Length < 4 * sizeof(wchar_t) || (memcmp(name.Buffer, L"api-", 4) != 0 && memcmp(name.Buffer, L"ext-", 4) != 0))
				return STATUS_NOT_FOUND;

			auto api_set_map_address{ reinterpret_cast<unsigned char*>(api_set_map) };
			for (unsigned long i{}; i < api_set_map->Count; i++) {
				#ifdef _WIN10_
				PAPISET_NAMESPACE_ENTRY descriptor{ reinterpret_cast<PAPISET_NAMESPACE_ENTRY>(
					api_set_map_address + api_set_map->End + i * sizeof(API_SET_NAMESPACE_ENTRY_10)) };
				PAPISET_VALUE_ARRAY host_array{ reinterpret_cast<PAPISET_VALUE_ARRAY>(
					api_set_map_address + api_set_map->Start + sizeof(API_SET_VALUE_ARRAY_10) * descriptor->Size) };

				wchar_t api_name_buffer[255]{};
				memcpy(api_name_buffer, api_set_map_address + host_array->NameOffset, host_array->NameLength);
				#else
				descriptor = api_set_map->Array + i;
				memcpy(api_name_buffer, api_set_map_address + descriptor->NameOffset, descriptor->NameLength);
				#endif

				UNICODE_STRING api_name{};
				RtlUnicodeStringInit(&api_name, api_name_buffer);

				// Check if this is a target api
				if (util::safe_find_string(name, api_name, true) >= 0)
				{
					#ifdef _WIN10_
					PAPISET_VALUE_ENTRY host{ reinterpret_cast<PAPISET_VALUE_ENTRY>(api_set_map_address + host_array->DataOffset) };
					#else
					host_array = reinterpret_cast<PAPISET_VALUE_ARRAY>(api_set_map_address + descriptor->DataOffset);
					host = host_array->Array;
					#endif

					// Sanity check
					if (host_array->Count < 1) return STATUS_NOT_FOUND;

					wchar_t api_host_name_buffer[255]{};
					memcpy(api_host_name_buffer, api_set_map_address + host->ValueOffset, host->ValueLength);

					UNICODE_STRING api_host_name{};
					RtlUnicodeStringInit(&api_host_name, api_host_name_buffer);

					// No base name redirection
					if (host_array->Count == 1 || base_image.Buffer[0] == 0)
					{
						util::safe_init_string(resolved, api_host_name);
						return STATUS_SUCCESS;
					}
					// Redirect accordingly to base name
					else
					{
						UNICODE_STRING base_image_name{};
						file::get_file_name(base_image, base_image_name);

						if (RtlCompareUnicodeString(&api_host_name, &base_image_name, TRUE) == 0)
						{
							memset(api_host_name_buffer, 0, sizeof(api_host_name_buffer));
							memcpy(api_host_name_buffer, api_set_map_address + host[1].ValueOffset, host[1].ValueLength);
							RtlCreateUnicodeString(&resolved, api_host_name_buffer);
							return STATUS_SUCCESS;
						}
						else
						{
							util::safe_init_string(resolved, api_host_name);
							return STATUS_SUCCESS;
						}
					}
				}
			}

			return STATUS_NOT_FOUND;
		}

		NTSTATUS resolve_sxs(PMMAP_CONTEXT context, const UNICODE_STRING& name, PUNICODE_STRING resolved) noexcept
		{
			typedef struct _STRIBG_BUF
			{
				union
				{
					UNICODE_STRING name1;
					UNICODE_STRING32 name132;
				};
				union
				{
					UNICODE_STRING name2;
					UNICODE_STRING32 name232;
				};
				union
				{
					UNICODE_STRING origName;
					UNICODE_STRING32 origName32;
				};
				union
				{
					PUNICODE_STRING pResolved;
					ULONG pResolved32;
				};
				wchar_t origBuf[0x100];
				wchar_t staticBuf[0x200];
			} STRIBG_BUF, * PSTRIBG_BUF;

			UNICODE_STRING ntdll = RTL_CONSTANT_STRING(L"ntdll.dll");
			bool wow64(PsGetProcessWow64Process(context->pProcess));
			auto string_buffer{ reinterpret_cast<PSTRIBG_BUF>(context->userMem->buffer) };
			auto ntdll_base{ module::get_user_module(context->pProcess, ntdll, wow64) };
			auto query_name{ module::get_module_export(ntdll_base, "RtlDosApplyFileIsolationRedirection_Ustr", context->pProcess, UNICODE_STRING()) };

			if (query_name == nullptr) return STATUS_NOT_FOUND;

			RtlZeroMemory(string_buffer->origBuf, sizeof(string_buffer->origBuf));
			RtlZeroMemory(string_buffer->staticBuf, sizeof(string_buffer->staticBuf));

			// Fill params
			memcpy(string_buffer->origBuf, name.Buffer, name.Length);
			if (wow64)
			{
				string_buffer->origName32.Buffer = static_cast<unsigned long>(reinterpret_cast<unsigned __int64>(string_buffer->origBuf));
				string_buffer->origName32.MaximumLength = sizeof(string_buffer->origBuf);
				string_buffer->origName32.Length = name.Length;

				string_buffer->name132.Buffer = static_cast<unsigned long>(reinterpret_cast<unsigned __int64>(string_buffer->staticBuf));
				string_buffer->name132.MaximumLength = sizeof(string_buffer->staticBuf);
				string_buffer->name132.Length = 0;

				string_buffer->name232.Buffer = 0;
				string_buffer->name232.Length = string_buffer->name232.MaximumLength = 0;
			}
			else
			{
				RtlInitUnicodeString(&string_buffer->origName, string_buffer->origBuf);
				RtlInitEmptyUnicodeString(&string_buffer->name1, string_buffer->staticBuf, sizeof(string_buffer->staticBuf));
				RtlInitEmptyUnicodeString(&string_buffer->name2, nullptr, 0);
			}

			// Prevent some unpredictable shit
			__try
			{
				// RtlDosApplyFileIsolationRedirection_Ustr
				NTSTATUS status{ call_routine(false, context, query_name,
					static_cast<unsigned __int64>(true),
					reinterpret_cast<unsigned __int64>(&string_buffer->origName),
					reinterpret_cast<unsigned __int64>(nullptr),
					reinterpret_cast<unsigned __int64>(&string_buffer->name1),
					reinterpret_cast<unsigned __int64>(&string_buffer->name2),
					reinterpret_cast<unsigned __int64>(&string_buffer->pResolved),
					reinterpret_cast<unsigned __int64>(nullptr), reinterpret_cast<unsigned __int64>(nullptr), reinterpret_cast<unsigned __int64>(nullptr)) };

				if (NT_SUCCESS(status) && NT_SUCCESS(context->userMem->status))
				{
					if (wow64)
					{
						unsigned long tmp{ reinterpret_cast<PUNICODE_STRING32>(string_buffer->pResolved32)->Buffer };
						string_buffer->pResolved = &string_buffer->name1;
						string_buffer->pResolved->Buffer = reinterpret_cast<wchar_t*>(tmp);
					}

					RtlDowncaseUnicodeString(resolved, string_buffer->pResolved, true);
					// TODO: name2 cleanup
				}

				return NT_SUCCESS(status) ? context->userMem->status : status;
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				return STATUS_UNHANDLED_EXCEPTION;
			}
		}

		NTSTATUS resolve_image_path(PMMAP_CONTEXT context, PEPROCESS process, resolve_flags flags, const UNICODE_STRING& path, const UNICODE_STRING& base_image,
			UNICODE_STRING& resolved) noexcept {
			UNICODE_STRING path_downcase{};
			RtlDowncaseUnicodeString(&path_downcase, &path, true);

			UNICODE_STRING file_name{};
			file::get_file_name(path_downcase, file_name);

			UNICODE_STRING full_resolved{};
			NTSTATUS status{ map::resolve_api_set(process, file_name, base_image, resolved) };
			if (NT_SUCCESS(status)) {
				util::safe_allocate_string(full_resolved, 512);
				if (PsGetProcessWow64Process(process)) {
					RtlUnicodeStringCatString(&full_resolved, L"\\SystemRoot\\syswow64\\");
				}
				else {
					RtlUnicodeStringCatString(&full_resolved, L"\\SystemRoot\\system32\\");
				}

				RtlUnicodeStringCat(&full_resolved, &resolved);
				RtlFreeUnicodeString(&resolved);
				RtlFreeUnicodeString(&path_downcase);

				resolved = full_resolved;
				return STATUS_SUCCESS;
			}

			if (flags & resolve_flags::api_shema_only) {
				resolved = path_downcase;
				return status;
			}
			else if (flags & resolve_flags::skip_sxs) {
				status = util::safe_allocate_string(full_resolved, 0x400);
				if (!NT_SUCCESS(status) || full_resolved.Buffer == nullptr) {
					RtlFreeUnicodeString(&resolved);
					RtlFreeUnicodeString(&path_downcase);
					return status;
				}

				status = ZwQueryInformationProcess(ZwCurrentProcess(), PROCESSINFOCLASS::ProcessImageFileName, full_resolved.Buffer + 0x100, 0x200, nullptr);
				if (NT_SUCCESS(status)) {
					UNICODE_STRING parent_directory{};
					file::get_directory_name(*reinterpret_cast<PUNICODE_STRING>(full_resolved.Buffer + 0x100), parent_directory);
					RtlUnicodeStringCatString(&full_resolved, L"\\");
					RtlUnicodeStringCat(&full_resolved, &file_name);
					if (NT_SUCCESS(file::exists(full_resolved))) {
						RtlFreeUnicodeString(&resolved);
						RtlFreeUnicodeString(&path_downcase);

						resolved = full_resolved;
						return STATUS_SUCCESS;
					}
				}

				full_resolved.Length = 0;
				RtlZeroMemory(full_resolved.Buffer, 0x400);

				//
				// System directory
				//
				if (PsGetProcessWow64Process(process) != NULL) {
					RtlUnicodeStringCatString(&full_resolved, L"\\SystemRoot\\SysWOW64\\");
				}
				else {
					RtlUnicodeStringCatString(&full_resolved, L"\\SystemRoot\\System32\\");
				}

				RtlUnicodeStringCat(&full_resolved, &file_name);
				if (NT_SUCCESS(file::exists(full_resolved)))
				{
					RtlFreeUnicodeString(&resolved);
					RtlFreeUnicodeString(&path_downcase);

					resolved = full_resolved;
					return STATUS_SUCCESS;
				}

				RtlFreeUnicodeString(&full_resolved);
				resolved = path_downcase;
				return status;
			}
			else {
				status = resolve_sxs(context, file_name, &resolved);
				if (context && NT_SUCCESS(status))
				{
					util::safe_allocate_string(full_resolved, 1024);
					RtlUnicodeStringCatString(&full_resolved, L"\\??\\");
					RtlUnicodeStringCat(&full_resolved, &resolved);

					RtlFreeUnicodeString(&resolved);
					RtlFreeUnicodeString(&path_downcase);

					resolved = full_resolved;
					return STATUS_SUCCESS;
				}
				else if (status == STATUS_UNHANDLED_EXCEPTION)
				{
					resolved = path_downcase;
					return status;
				}
				else {
					status = STATUS_SUCCESS;
				}

				return status;
			}
		}
	}
}