#include "handle.hpp"

namespace handle {
	PHANDLE_TABLE_ENTRY exp_lookup_handle_table_entry(PHANDLE_TABLE handle_table, EXHANDLE handle) noexcept
	{
		const auto table_code{ handle_table->TableCode & 3 };
		if (handle.Value >= handle_table->NextHandleNeedingPool) return nullptr;

		handle.Value &= 0xFFFFFFFFFFFFFFFC;

		#if defined ( _WIN10_ )
		if (table_code != 0) {
			if (table_code == 1) {
				return reinterpret_cast<PHANDLE_TABLE_ENTRY>(
					*reinterpret_cast<unsigned __int64*>(handle_table->TableCode + 8 * (handle.Value >> 11) - 1) + 4 * (handle.Value & 0x7FC));
			}
			else {
				return reinterpret_cast<PHANDLE_TABLE_ENTRY>(*reinterpret_cast<unsigned __int64*>(*reinterpret_cast<unsigned __int64*>(
						handle_table->TableCode + 8 * (handle.Value >> 21) - 2) + 8 * (handle.Value >> 11 & 0x3FF)) + 4 * (handle.Value & 0x7FC));
			}
		}
		else {
			return reinterpret_cast<PHANDLE_TABLE_ENTRY>(handle_table->TableCode + 4 * handle.Value);
		}
		#elif defined ( _WIN7_ )
		auto diff{ handle_table->TableCode - TableCode };

		if (table_code != 0)
		{
			if (table_code == 1)
			{
				return reinterpret_cast<PHANDLE_TABLE_ENTRY>(*reinterpret_cast<unsigned __int64*>(
					diff + ((handle.Value - handle.Value & 0x7FC) >> 9)) + 4 * (handle.Value & 0x7FC));
			}
			else
			{
				unsigned __int64 tmp{ (handle.Value - handle.Value & 0x7FC) >> 9 };
				return reinterpret_cast<PHANDLE_TABLE_ENTRY>(*reinterpret_cast<unsigned __int64*>(
					*reinterpret_cast<unsigned __int64*>(diff + ((handle.Value - tmp - tmp & 0xFFF) >> 10)) + (tmp & 0xFFF)) + 4 * (handle.Value & 0x7FC));
			}
		}
		else
		{
			return reinterpret_cast<PHANDLE_TABLE_ENTRY>(diff + 4 * handle.Value);
		}
		#else
		if (table_code != 0)
		{
			if (table_code == 1)
			{
				return reinterpret_cast<PHANDLE_TABLE_ENTRY>(*reinterpret_cast<unsigned __int64*>(
					handle_table->TableCode + 8 * (handle.Value >> 10) - 1) + 4 * (handle.Value & 0x3FF));
			}
			else
			{
				auto tmp{ handle.Value >> 10 };
				return reinterpret_cast<PHANDLE_TABLE_ENTRY>(*reinterpret_cast<unsigned __int64*>(
					*reinterpret_cast<unsigned __int64*>(handle_table->TableCode + 8 * (handle.Value >> 19) - 2) + 8 * (tmp & 0x1FF)) + 4 * (handle.Value & 0x3FF));
			}
		}
		else
		{
			return (PHANDLE_TABLE_ENTRY)(handle_table->TableCode + 4 * handle.Value);
		}
		#endif
	}

	struct handle_enum_parameter {
		unsigned int access;
		HANDLE handle;
	};

	NTSTATUS grant_access(PEPROCESS process, unsigned int access, HANDLE handle /*= INVALID_HANDLE_VALUE */) noexcept {
		auto object_table{ compatibility::get_data().object_table };
		if (object_table == 0) { return STATUS_NOT_IMPLEMENTED; }

		if (process::is_terminating(process)) { return STATUS_PROCESS_IS_TERMINATING; }
		handle_enum_parameter parameter{ access , handle };

		PHANDLE_TABLE handle_table{ *reinterpret_cast<PHANDLE_TABLE*>(reinterpret_cast<unsigned char*>(process) + object_table) };
		if (!ExEnumHandleTable(handle_table, [](
			#if !defined(_WIN7_)
			PHANDLE_TABLE handle_table,
			#endif
			PHANDLE_TABLE_ENTRY handle_table_entry, HANDLE handle [[maybe_unused]], void* enum_parameter) -> BOOLEAN {
			bool status{ false };
			if (enum_parameter != nullptr) {
				const auto parameter{ *reinterpret_cast<handle_enum_parameter*>(enum_parameter) };
				if (ExpIsValidObjectEntry(handle_table_entry)) {
					if (parameter.handle != INVALID_HANDLE_VALUE) {
						if (parameter.handle == handle) {
							handle_table_entry->GrantedAccessBits = parameter.access;
							status = true;
						}
					}
					else {
						handle_table_entry->GrantedAccessBits = parameter.access;
					}
				}
			}

			#if !defined(_WIN7_)
			// Release implicit locks
			if(handle_table_entry) _InterlockedExchangeAdd8(reinterpret_cast<char*>(&handle_table_entry->VolatileLowValue), 1);  // Set Unlocked flag to 1
			if (handle_table != NULL && handle_table->HandleContentionEvent)
				ExfUnblockPushLock(&handle_table->HandleContentionEvent, NULL);
			#endif

			return status;
		}, &parameter, nullptr) && handle != INVALID_HANDLE_VALUE) {
			return STATUS_NOT_FOUND;
		}

		return STATUS_SUCCESS;
	}

	NTSTATUS close_handle(PEPROCESS process, HANDLE handle) noexcept {
		__try {
			const bool attach{ PsGetCurrentProcessId() != PsGetProcessId(process) };
			KAPC_STATE state{};
			if (attach) KeStackAttachProcess(process, &state);

			KPROCESSOR_MODE mode{ MODE::UserMode };
			if (IoGetCurrentProcess() == PsInitialSystemProcess) {
				*reinterpret_cast<unsigned __int64*>(handle) |= KERNEL_HANDLE_MASK;
				mode = MODE::KernelMode;
			}

			OBJECT_HANDLE_FLAG_INFORMATION info{};
			info.Inherit = false;
			info.ProtectFromClose = false;
			auto status{ ObSetHandleAttributes(handle, &info, mode) };
			if (NT_SUCCESS(status)) {
				status = ZwClose(handle);
			}

			KeUnstackDetachProcess(&state);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			return _exception_code();
		}
	}

	NTSTATUS close_handle_by_id(HANDLE process_id, HANDLE handle) noexcept {
		PEPROCESS process{};
		const auto status{ PsLookupProcessByProcessId(process_id, &process) };
		if (!NT_SUCCESS(status)) return status;

		return close_handle(process, handle);
	}
}