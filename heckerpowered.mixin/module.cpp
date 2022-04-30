#include "module.hpp"

namespace module {
	typedef struct _INJECT_BUFFER
	{
		UCHAR code[0x200];
		union
		{
			UNICODE_STRING path;
			UNICODE_STRING32 path32;
		};

		wchar_t buffer[488];
		PVOID module;
		ULONG complete;
		NTSTATUS status;
	} INJECT_BUFFER, * PINJECT_BUFFER;

	PINJECT_BUFFER get_inject_code_x86(void* ldr_load_dll [[maybe_unused]], const UNICODE_STRING& path) {
		unsigned char code[] =
		{
			0x68, 0, 0, 0, 0,                       // push ModuleHandle            offset +1 
			0x68, 0, 0, 0, 0,                       // push ModuleFileName          offset +6
			0x6A, 0,                                // push Flags  
			0x6A, 0,                                // push PathToFile
			0xE8, 0, 0, 0, 0,                       // call LdrLoadDll              offset +15
			0xBA, 0, 0, 0, 0,                       // mov edx, COMPLETE_OFFSET     offset +20
			0xC7, 0x02, 0x7E, 0x1E, 0x37, 0xC0,     // mov [edx], CALL_COMPLETE     
			0xBA, 0, 0, 0, 0,                       // mov edx, STATUS_OFFSET       offset +31
			0x89, 0x02,                             // mov [edx], eax
			0xC2, 0x04, 0x00                        // ret 4
		};

		PINJECT_BUFFER buffer{};
		size_t size{};
		NTSTATUS status{ ZwAllocateVirtualMemory(ZwCurrentProcess(), reinterpret_cast<void**>(&buffer), 0, &size, MEM_COMMIT, PAGE_EXECUTE_READWRITE) };
		if (!NT_SUCCESS(status)) return nullptr;

		// Copy path
		PUNICODE_STRING32 user_path{ &buffer->path32 };
		user_path->Length = path.Length;
		user_path->MaximumLength = path.MaximumLength;
		user_path->Buffer = static_cast<unsigned long>(reinterpret_cast<unsigned __int64>(buffer->buffer));

		// Copy path
		memcpy(reinterpret_cast<void*>(user_path->Buffer), path.Buffer, path.Length);

		// Copy code
		memcpy(buffer, code, sizeof(code));

		// Fill stubs
		*reinterpret_cast<unsigned long*>(reinterpret_cast<unsigned char*>(buffer) + 1) = static_cast<unsigned long>(
			reinterpret_cast<unsigned __int64>(&buffer->module));
		*reinterpret_cast<unsigned long*>(reinterpret_cast<unsigned char*>(buffer) + 6) = static_cast<unsigned long>(
			reinterpret_cast<unsigned __int64>(user_path));
		*reinterpret_cast<unsigned long*>(reinterpret_cast<unsigned char*>(buffer) + 15) = 
			static_cast<unsigned long>(reinterpret_cast<unsigned __int64>(ldr_load_dll) - (reinterpret_cast<unsigned __int64>(buffer) + 15) - 5 + 1);
		*reinterpret_cast<unsigned long*>(reinterpret_cast<unsigned char*>(buffer) + 20) = static_cast<unsigned long>(
			reinterpret_cast<unsigned __int64>(&buffer->complete));
		*reinterpret_cast<unsigned long*>(reinterpret_cast<unsigned char*>(buffer) + 31) = static_cast<unsigned long>(
			reinterpret_cast<unsigned __int64>(&buffer->status));

		return buffer;
	}

	PINJECT_BUFFER get_inject_code_x64(void* ldr_load_dll, const UNICODE_STRING& path) {
		unsigned char code[] =
		{
			0x48, 0x83, 0xEC, 0x28,                 // sub rsp, 0x28
			0x48, 0x31, 0xC9,                       // xor rcx, rcx
			0x48, 0x31, 0xD2,                       // xor rdx, rdx
			0x49, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0,     // mov r8, ModuleFileName   offset +12
			0x49, 0xB9, 0, 0, 0, 0, 0, 0, 0, 0,     // mov r9, ModuleHandle     offset +28
			0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0,     // mov rax, LdrLoadDll      offset +32
			0xFF, 0xD0,                             // call rax
			0x48, 0xBA, 0, 0, 0, 0, 0, 0, 0, 0,     // mov rdx, COMPLETE_OFFSET offset +44
			0xC7, 0x02, 0x7E, 0x1E, 0x37, 0xC0,     // mov [rdx], CALL_COMPLETE 
			0x48, 0xBA, 0, 0, 0, 0, 0, 0, 0, 0,     // mov rdx, STATUS_OFFSET   offset +60
			0x89, 0x02,                             // mov [rdx], eax
			0x48, 0x83, 0xC4, 0x28,                 // add rsp, 0x28
			0xC3                                    // ret
		};

		PINJECT_BUFFER buffer{};
		size_t size{};
		NTSTATUS status{ ZwAllocateVirtualMemory(ZwCurrentProcess(), reinterpret_cast<void**>(&buffer), 0, &size, MEM_COMMIT, PAGE_EXECUTE_READWRITE) };
		if (!NT_SUCCESS(status)) return nullptr;

		PUNICODE_STRING user_path{ &buffer->path };
		user_path->Length = 0;
		user_path->MaximumLength = sizeof(buffer->buffer);
		user_path->Buffer = buffer->buffer;

		RtlUnicodeStringCopy(user_path, &path);

		// Copy code
		memcpy(buffer, code, sizeof(code));

		// Fill stubs
		*reinterpret_cast<unsigned __int64*>(reinterpret_cast<unsigned char*>(buffer) + 12) = reinterpret_cast<unsigned __int64>(user_path);
		*reinterpret_cast<unsigned __int64*>(reinterpret_cast<unsigned char*>(buffer) + 22) = reinterpret_cast<unsigned __int64>(&buffer->module);
		*reinterpret_cast<unsigned __int64*>(reinterpret_cast<unsigned char*>(buffer) + 32) = reinterpret_cast<unsigned __int64>(ldr_load_dll);
		*reinterpret_cast<unsigned __int64*>(reinterpret_cast<unsigned char*>(buffer) + 44) = reinterpret_cast<unsigned __int64>(&buffer->complete);
		*reinterpret_cast<unsigned __int64*>(reinterpret_cast<unsigned char*>(buffer) + 60) = reinterpret_cast<unsigned __int64>(&buffer->status);

		return buffer;
	}

	void* get_user_module(PEPROCESS process, const UNICODE_STRING& module_name, bool is_wow64) noexcept {
		__try {
			if (is_wow64) {
				auto peb32{ reinterpret_cast<PPEB32>(PsGetProcessWow64Process(process)) };
				if (peb32 == nullptr) return nullptr;

				if (!peb32->Ldr) return nullptr;

				for (auto list_entry{ reinterpret_cast<PLIST_ENTRY32>(reinterpret_cast<PPEB_LDR_DATA32>(peb32->Ldr)->InLoadOrderModuleList.Flink) };
					list_entry != &reinterpret_cast<PPEB_LDR_DATA32>(peb32->Ldr)->InLoadOrderModuleList;
					list_entry = reinterpret_cast<PLIST_ENTRY32>(list_entry->Flink))
				{
					PLDR_DATA_TABLE_ENTRY32 entry{ CONTAINING_RECORD(list_entry, LDR_DATA_TABLE_ENTRY32, InLoadOrderLinks) };
					UNICODE_STRING string RTL_CONSTANT_STRING((reinterpret_cast<wchar_t*>(entry->BaseDllName.Buffer)));
					if (RtlCompareUnicodeString(&string, &module_name, true) == 0)  return reinterpret_cast<void*>(entry->DllBase);
				}
			}
			else {
				auto peb{ PsGetProcessPeb(process) };
				if (peb == nullptr) return nullptr;
				if (peb->Ldr == nullptr) return nullptr;

				for (auto list_entry{ peb->Ldr->InLoadOrderModuleList.Flink };
					list_entry != &peb->Ldr->InLoadOrderModuleList;
					list_entry = list_entry->Flink)
				{
					PLDR_DATA_TABLE_ENTRY entry{ CONTAINING_RECORD(list_entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks) };
					if (RtlCompareUnicodeString(&entry->BaseDllName, &module_name, TRUE) == 0) return entry->DllBase;
				}
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			return nullptr;
		}

		return nullptr;
	}

	void* get_module_export(void* module, const char* name_ordinal, PEPROCESS process, const UNICODE_STRING& name) noexcept {
		PIMAGE_DOS_HEADER dos_header{ reinterpret_cast<PIMAGE_DOS_HEADER>(module) };
		if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;

		auto nt_headers{ reinterpret_cast<unsigned char*>(module) + dos_header->e_lfanew };
		PIMAGE_NT_HEADERS32 nt_headers32{ reinterpret_cast<PIMAGE_NT_HEADERS32>(nt_headers) };
		PIMAGE_NT_HEADERS64 nt_headers64{ reinterpret_cast<PIMAGE_NT_HEADERS64>(nt_headers) };

		if (nt_headers32->Signature != IMAGE_NT_SIGNATURE) return nullptr;

		PIMAGE_EXPORT_DIRECTORY export_directory;
		size_t size;
		auto module_address{ reinterpret_cast<unsigned __int64>(module) };
		if (nt_headers32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
			auto data_directory{ nt_headers64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT] };
			export_directory = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(data_directory.VirtualAddress)
				+ module_address;
			size = data_directory.Size;
		}
		else {
			auto data_directory{ nt_headers32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT] };
			export_directory = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(data_directory.VirtualAddress)
				+ module_address;
			size = data_directory.Size;
		}

		auto oridinals{ reinterpret_cast<unsigned short*>(export_directory->AddressOfNameOrdinals + module_address) };
		auto names{ reinterpret_cast<unsigned long*>(export_directory->AddressOfNames + module_address) };
		auto functions{ reinterpret_cast<unsigned long*>(export_directory->AddressOfFunctions + module_address) };
		unsigned __int64 address{};
		auto export_address{ reinterpret_cast<unsigned __int64>(export_directory) };
		for (unsigned int i{}; i < export_directory->NumberOfFunctions; i++) {
			unsigned short oridinal_index{ 0xFFFF };
			auto oridinal{ reinterpret_cast<unsigned __int64>(name_ordinal) };
			char* module_name{};
			if (oridinal <= 0xFFFF) {
				oridinal_index = unsigned short(i);
			}
			else if (oridinal > 0xFFFF && i < export_directory->NumberOfNames) {
				module_name = reinterpret_cast<char*>(names[i] + module_address);
				oridinal_index = oridinals[i];
			}
			else {
				return nullptr;
			}

			if ((oridinal <= 0xFFFF && oridinal == static_cast<unsigned __int64>(oridinal_index) + export_directory->Base) ||
				(oridinal > 0xFFFF && std::char_traits<char>::compare(module_name, name_ordinal, std::char_traits<char>::length(module_name)) == 0)) {
				address = functions[oridinal_index] + module_address;

				if (address > export_address && address <= export_address + size) {
					ANSI_STRING ansi_forwarder{};
					RtlInitAnsiString(&ansi_forwarder, reinterpret_cast<const char*>(address));

					UNICODE_STRING unicode_forwarder{};
					wchar_t buffer[256]{};
					RtlInitEmptyUnicodeString(&unicode_forwarder, buffer, sizeof(buffer));
					RtlAnsiStringToUnicodeString(&unicode_forwarder, &ansi_forwarder, false);

					unsigned long index{};
					auto maxium{ unicode_forwarder.Length / sizeof(wchar_t) };
					for (unsigned long j{}; j < maxium; j++)
					{
						if (unicode_forwarder.Buffer[j] != L'.') continue;

						unicode_forwarder.Length = static_cast<unsigned short>(j * sizeof(wchar_t));
						unicode_forwarder.Buffer[j] = L'\0';
						index = j;
						break;
					}

					ANSI_STRING import{};
					RtlInitAnsiString(&import, ansi_forwarder.Buffer + index + 1);
					RtlAppendUnicodeToString(&unicode_forwarder, L".dll");

					// Check forwarded module
					UNICODE_STRING resolved{};
					map::resolve_image_path(nullptr, process, map::resolve_flags::api_shema_only, unicode_forwarder, name, resolved);

					UNICODE_STRING resolved_name{};
					file::get_file_name(resolved, resolved_name);

					void* forward_base{ get_user_module(process, resolved_name, PsGetProcessWow64Process(process)) };
					void* result{ get_module_export(forward_base, import.Buffer, process, resolved_name) };
					RtlFreeUnicodeString(&resolved);
					return result;
				}

				break;
			}
		}

		return reinterpret_cast<void*>(address);
	}
}