#include "process.hpp"

namespace process
{
	NTSTATUS get_process_by_id(void* process_id, PEPROCESS& process) noexcept
	{
		return PsLookupProcessByProcessId(process_id, &process);
	}

	NTSTATUS open_process_by_id(void* process_id, void*& process, unsigned int access_mask) noexcept
	{
		PEPROCESS eprocess;
		auto status = PsLookupProcessByProcessId(process_id, &eprocess);
		if (!NT_SUCCESS(status)) return status;

		status = ObOpenObjectByPointer(eprocess, 0, nullptr, access_mask, *PsProcessType, MODE::KernelMode, &process);
		ObDereferenceObject(eprocess);
		return status;
	}

	NTSTATUS open_process(PEPROCESS process, void*& handle, unsigned int access_mask, unsigned int attributes, KPROCESSOR_MODE processor_mode) noexcept
	{
		return ObOpenObjectByPointer(process, attributes, nullptr, access_mask, *PsProcessType, processor_mode, &handle);
	}

	NTSTATUS terminate_process(PEPROCESS process, NTSTATUS exit_status) noexcept
	{
		void* handle;
		auto status = open_process(process, handle);
		if (NT_SUCCESS(status))
		{

			// To obtain a process handle that a driver can specify for the ProcessHandle parameter, the driver can call
			// ZwOpenProcess. The handle must be a kernel handle, a handle that can only be accessed in kernel mode. A handle
			// is a kernel handle if it is created with the OBJ_KERNEL_HANDLE flag. For more info see InitializeObjectAttributes.
			//
			// Drivers must not specify the current process if resources have not been freed from the kernel stack, because the
			// operating system will not unwind the kernel stack for the calling thread.
			//
			// For calls from kernel-mode drivers, the NtXxx and ZwXxx versions of a Windows Native System Services routine
			// can behave differently in the way that they handle and interpret input parameters. For more information about
			//	the relationship between the NtXxx and ZwXxx versions of a routine.
			status = ZwTerminateProcess(handle, exit_status);
			ZwClose(handle);
		}

		return status;
	}

	NTSTATUS terminate_process_by_id(void* process, NTSTATUS exit_status) noexcept
	{
		void* handle;
		auto status = open_process_by_id(process, handle);
		if (NT_SUCCESS(status))
		{

			// To obtain a process handle that a driver can specify for the ProcessHandle parameter, the driver can call
			// ZwOpenProcess. The handle must be a kernel handle, a handle that can only be accessed in kernel mode. A handle
			// is a kernel handle if it is created with the OBJ_KERNEL_HANDLE flag. For more info see InitializeObjectAttributes.
			//
			// Drivers must not specify the current process if resources have not been freed from the kernel stack, because the
			// operating system will not unwind the kernel stack for the calling thread.
			//
			// For calls from kernel-mode drivers, the NtXxx and ZwXxx versions of a Windows Native System Services routine
			// can behave differently in the way that they handle and interpret input parameters. For more information about
			//	the relationship between the NtXxx and ZwXxx versions of a routine.
			status = ZwTerminateProcess(handle, exit_status);
			ZwClose(handle);
		}

		return status;
	}

	NTSTATUS suspend_process(PEPROCESS process) noexcept
	{
		using PsSuspendProcess = NTSTATUS(__stdcall*)(PEPROCESS);

		static auto _suspend_process{ reinterpret_cast<PsSuspendProcess>(proc::get_kernel_procedure(L"PsSuspendProcess")) };
		if (_suspend_process)
			return _suspend_process(process);

		return STATUS_NOT_IMPLEMENTED;
	}

	NTSTATUS suspend_process_by_id(void* process_id) noexcept
	{
		PEPROCESS process;
		const auto status = get_process_by_id(process_id, process);
		if (!NT_SUCCESS(status))
		{
			return status;
		}

		return suspend_process(process);
	}

	NTSTATUS resume_process(PEPROCESS process) noexcept
	{
		using PsResumeProcess = NTSTATUS(__stdcall*)(PEPROCESS);

		static auto suspend_process{ reinterpret_cast<PsResumeProcess>(proc::get_kernel_procedure(L"PsResumeProcess")) };
		if (suspend_process)
			return suspend_process(process);

		return STATUS_NOT_IMPLEMENTED;
	}

	NTSTATUS resume_process_by_id(void* process_id) noexcept
	{
		PEPROCESS process;
		const auto status = get_process_by_id(process_id, process);
		if (!NT_SUCCESS(status))
		{
			return status;
		}

		return resume_process(process);
	}

	NTSTATUS query_information_process(void* process, PROCESSINFOCLASS process_information_class, void* process_information,
		unsigned int process_information_length, unsigned int& return_length) noexcept
	{
		using ZwQueryInformationProcess = NTSTATUS(__stdcall*)(void*, PROCESSINFOCLASS, void*, unsigned int, unsigned int*);

		static auto query_information_process{ reinterpret_cast<ZwQueryInformationProcess>(proc::get_kernel_procedure(L"ZwQueryInformationProcess")) };
		if (query_information_process)
			query_information_process(process, process_information_class, process_information, process_information_length, &return_length);

		return STATUS_NOT_IMPLEMENTED;
	}

	NTSTATUS set_information_process(void* process, PROCESSINFOCLASS process_information_class, void* process_information,
		unsigned int process_information_length) noexcept
	{
		using ZwSetInformationProcess = NTSTATUS(__stdcall*)(void*, PROCESSINFOCLASS, void*, unsigned int);

		static auto set_information_process{ reinterpret_cast<ZwSetInformationProcess>(proc::get_kernel_procedure(L"ZwSetInformationProcess")) };
		if (set_information_process)
			return set_information_process(process, process_information_class, process_information, process_information_length);

		return STATUS_NOT_IMPLEMENTED;
	}

	bool is_32bit(void* process) noexcept
	{
		unsigned __int64 is_wow64 = 0;
		unsigned int return_length;

		const auto status = query_information_process(process, ProcessWow64Information, &is_wow64, sizeof(is_wow64), return_length);
		if (!NT_SUCCESS(status) || !return_length)
			return false;

		return is_wow64 != 0;
	}

	bool is_32bit_by_id(void* process_id) noexcept
	{
		void* handle;
		const auto status = open_process_by_id(process_id, handle);
		if (!NT_SUCCESS(status))
		{
			return status;
		}

		const auto result = is_32bit(handle);
		ZwClose(handle);
		return result;
	}

	bool is_64bit(PEPROCESS process) noexcept
	{
		return PsGetProcessWow64Process(process);
	}

	bool is_64bit_by_id(void* process_id) noexcept
	{
		PEPROCESS process;
		const auto status{ PsLookupProcessByProcessId(process_id, &process) };
		if (!NT_SUCCESS(status)) return status;

		const auto result{ is_64bit(process) };
		ObDereferenceObject(process);

		return result;
	}

	bool is_terminating(PEPROCESS process) noexcept
	{
		LARGE_INTEGER zero_time{};
		return KeWaitForSingleObject(process, KWAIT_REASON::Executive, MODE::KernelMode, false, &zero_time) == STATUS_WAIT_0;
	}

	NTSTATUS lookup_process_thread(PEPROCESS process, std::vector<PETHREAD>& threads)
	{
		auto buffer{ mem::allocate(1024 * 1024) };
		if (buffer == nullptr) return STATUS_INSUFFICIENT_RESOURCES;

		NTSTATUS status{ ZwQuerySystemInformation(SYSTEM_INFORMATION_CLASS::SystemProcessInformation, buffer, 1024 * 1024, nullptr) };
		if (!NT_SUCCESS(status))
		{
			mem::free(buffer);
			return status;
		}

		auto process_id{ PsGetProcessId(process) };

		auto info{ static_cast<PSYSTEM_PROCESS_INFO>(buffer) };
		while (true)
		{
			if (info->UniqueProcessId == process_id)
			{
				break;
			}
			else if (info->NextEntryOffset)
			{
				info = reinterpret_cast<PSYSTEM_PROCESS_INFO>(reinterpret_cast<unsigned char*>(info) + info->NextEntryOffset);
			}
			else
			{
				status = STATUS_NOT_FOUND;
				break;
			}
		}

		if (!NT_SUCCESS(status))
		{
			mem::free(buffer);
			return status;
		}

		for (unsigned long i{}; i < info->NumberOfThreads; i++)
		{
			PETHREAD thread;
			status = PsLookupThreadByThreadId(info->Threads[i].ClientId.UniqueThread, &thread);
			if (!NT_SUCCESS(status)) break;

			threads.push_back(thread);
		}

		return status;
	}

	bool satisfy_apc_requirements(PETHREAD thread, bool wow64) noexcept
	{
		unsigned char* teb{ reinterpret_cast<unsigned char*>(PsGetThreadTeb(thread)) };
		if (!teb) return false;

		// Skip GUI treads. APC to GUI thread causes ZwUserGetMessage to fail
		// TEB64 + 0x78  = Win32ThreadInfo
		if (*reinterpret_cast<unsigned __int64*>(teb + 0x78) != 0) return false;

		if (wow64)
		{
			unsigned char* teb32{ teb + 0x2000 };

			// TEB32 + 0x1A8 = ActivationContextStackPointer
			if (*reinterpret_cast<unsigned int*>(teb32 + 0x1A8) == 0) return false;

			// TEB64 + 0x2C = ThreadLocalStoragePointer
			if (*reinterpret_cast<unsigned int*>(teb32 + 0x2C) == 0) return false;
		}
		else
		{

			// TEB64 + 0x2C8 = ActivationContextStackPointer
			if (*reinterpret_cast<unsigned __int64*>(teb + 0x2C8) == 0) return false;

			// TEB64 + 0x58 = ThreadLocalStoragePointer
			if (*reinterpret_cast<unsigned __int64*>(teb + 0x58) == 0) return false;
		}

		return true;
	}

	NTSTATUS set_protect_flag(PEPROCESS process, protect_flag protection, protect_flag dynamic_code, protect_flag signature) noexcept
	{
		auto&& data{ compatibility::get_data() };
		if (data.protection == 0) return STATUS_NOT_IMPLEMENTED;

		auto value{ reinterpret_cast<unsigned char*>(process) + data.protection };
		const auto version{ data.version };

		if (version <= compatibility::windows_version::WINVER_7_SP1)
		{
			if (protection == protect_flag::enable)
			{
				*reinterpret_cast<unsigned long*>(value) |= 1 << 0xB;
			}
			else if (protection == protect_flag::disable)
			{
				*reinterpret_cast<unsigned long*>(value) &= ~(1 << 0xB);
			}
		}
		else if (version == compatibility::windows_version::WINVER_8)
		{
			if (protection != protect_flag::enable)
			{
				*value = static_cast<unsigned char>(protection);
			}
		}
		else if (version >= compatibility::windows_version::WINVER_81)
		{
			if (protection == protect_flag::disable)
			{
				*value = 0;
			}
			else if (protection == protect_flag::enable)
			{
				PS_PROTECTION buffer{};
				buffer.Flags.Signer = PS_PROTECTED_SIGNER::PsProtectedSignerMax;
				buffer.Flags.Type = PS_PROTECTED_TYPE::PsProtectedTypeMax;
				*value = buffer.Level;
			}

			if (dynamic_code != protect_flag::keep && data.eprocess_flag2 != 0)
			{
				if (data.version >= compatibility::windows_version::WINVER_10_RS3)
				{
					auto flags{ reinterpret_cast<PMITIGATION_FLAGS>(reinterpret_cast<unsigned char*>(process) + data.eprocess_flag2) };
					flags->DisableDynamicCode = static_cast<unsigned int>(dynamic_code);
				}
				else
				{
					auto flags{ reinterpret_cast<PEPROCESS_FLAGS2>(reinterpret_cast<unsigned char*>(process) + data.eprocess_flag2) };
					flags->DisableDynamicCode = static_cast<unsigned int>(dynamic_code);
				}
			}

			if (signature != protect_flag::keep)
			{
				auto signing_level{ reinterpret_cast<PSE_SIGNING_LEVEL>(reinterpret_cast<unsigned char*>(process) + data.protection - 2) };
				auto signing_level_section{ reinterpret_cast<PSE_SIGNING_LEVEL>(reinterpret_cast<unsigned char*>(process) + data.protection - 1) };

				if (signature == protect_flag::enable)
				{
					*signing_level = *signing_level_section = SE_SIGNING_LEVEL_MICROSOFT;
				}
				else
				{
					*signing_level = *signing_level_section = SE_SIGNING_LEVEL_UNCHECKED;
				}
			}
		}
		else
		{
			return STATUS_NOT_SUPPORTED;
		}

		return STATUS_SUCCESS;
	}
	NTSTATUS set_protect_flag_by_id(HANDLE process_id, protect_flag protection, protect_flag dynamic_code, protect_flag signature) noexcept
	{
		PEPROCESS process;
		const auto status{ PsLookupProcessByProcessId(process_id,&process) };
		if (!NT_SUCCESS(status)) return status;

		return set_protect_flag(process, protection, dynamic_code, signature);
	}
}