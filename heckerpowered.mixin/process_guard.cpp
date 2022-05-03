#include "process_guard.hpp"

namespace guard
{

	// For containers that do not require a constructor, we can
	// declare global variables/static local variables and use them
	// directly, but we must declare an empty container (if it is a 
	// global variable or a static local variable), otherwise it will cause
	// problems. For containers that require constructors, we need to
	// use pointers when declaring global variables and static local
	// variables.
	std::unordered_map<HANDLE, guard_level>* guarded_processes;

	void raise_guard_level(HANDLE process_id, guard_level level) noexcept
	{
		(*guarded_processes)[process_id] = level;
		if (level >= guard_level::strict)
		{
			process::set_protect_flag_by_id(process_id, process::protect_flag::enable, process::protect_flag::enable, process::protect_flag::enable);
		}
		else
		{
			process::set_protect_flag_by_id(process_id, process::protect_flag::disable, process::protect_flag::disable, 
				process::protect_flag::disable);
		}
	}

	void disable_guard(void* process_id) noexcept
	{
		guarded_processes->erase(process_id);
		process::set_protect_flag_by_id(process_id, process::protect_flag::disable, process::protect_flag::disable, process::protect_flag::disable);
	}

	bool guarded(void* process_id) noexcept
	{
		return require(process_id, guard_level::basic);
	}

	bool require(HANDLE process_id, guard_level level) noexcept
	{
		auto result{ guarded_processes->find(process_id) };
		if (result == guarded_processes->end()) { return false; }
		return result->second >= level;
	}

	void initialize()
	{

		// Local static objects are constructed at first run time or at load
		// time, static objects are constructed at load time, both add
		// elements to the global destructor pointer container at 
		// construction time and destruct at unload time
		guarded_processes = new std::unordered_map<HANDLE, guard_level>;

		#pragma region INFINITY HOOK
		hook::hook_export(L"NtOpenProcess", static_cast<NTSTATUS(*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID)>(
			[](_Out_ PHANDLE ProcessHandle, _In_ ACCESS_MASK DesiredAccess, _In_ POBJECT_ATTRIBUTES ObjectAttributes, _In_opt_ PCLIENT_ID ClientId)
		{
			if (ClientId && guarded(ClientId->UniqueProcess)) return STATUS_ACCESS_DENIED;

			return NtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
		}));

		hook::hook_ssdt("NtTerminateThread", static_cast<NTSTATUS(*)(HANDLE, NTSTATUS)>([](HANDLE ThreadHandle, NTSTATUS ExitStatus)
		{
			if (ThreadHandle)
			{
				PETHREAD thread{};
				if (NT_SUCCESS(ObReferenceObjectByHandle(ThreadHandle, THREAD_ALL_ACCESS, *PsThreadType, MODE::KernelMode, reinterpret_cast<void**>(&thread)
					, nullptr)))
				{
					if (guarded(PsGetProcessId(IoThreadToProcess(thread)))) return STATUS_ACCESS_DENIED;
				}
			}

			static auto NtTerminateThread{ static_cast<NTSTATUS(*)(HANDLE, NTSTATUS)>(ext::get_ssdt_entry(ssdt::get_ssdt_index("NtTerminateThread"))) };
			return NtTerminateThread(ThreadHandle, ExitStatus);
		}));

		hook::hook_export(L"NtOpenThread", static_cast<NTSTATUS(*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID)>(
			[](_Out_ PHANDLE ThreadHandle, _In_ ACCESS_MASK DesiredAccess, _In_ POBJECT_ATTRIBUTES ObjectAttributes, _In_ PCLIENT_ID ClientId)
		{
			if (guarded(ClientId->UniqueProcess)){ return STATUS_ACCESS_DENIED; }

			return NtOpenThread(ThreadHandle, DesiredAccess, ObjectAttributes, ClientId);
		}));

		using NtQuerySystemInformation_t = NTSTATUS(*)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);
		hook::hook_ssdt("NtQuerySystemInformation", static_cast<NtQuerySystemInformation_t>(
			[](SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength)
		{
			static auto NtQuerySystemInformation{
				static_cast<NtQuerySystemInformation_t>(ext::get_ssdt_entry(ssdt::get_ssdt_index("NtQuerySystemInformation"))) };
			auto status{ NtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength) };

			if (NT_SUCCESS(status) && SystemInformationClass == SYSTEM_INFORMATION_CLASS::SystemProcessInformation)
			{
				typedef struct _SYSTEM_PROCESS_INFORMATION
				{
					ULONG                   NextEntryOffset;
					ULONG                   NumberOfThreads;
					LARGE_INTEGER           Reserved[3];
					LARGE_INTEGER           CreateTime;
					LARGE_INTEGER           UserTime;
					LARGE_INTEGER           KernelTime;
					UNICODE_STRING          ImageName;
					ULONG                   BasePriority;
					HANDLE                  ProcessId;
					HANDLE                  InheritedFromProcessId;
				} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

				PSYSTEM_PROCESS_INFORMATION current{};
				auto next{ reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(SystemInformation) };

				do
				{
					current = next;
					next = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(reinterpret_cast<unsigned char*>(current) + current->NextEntryOffset);

					if (guard::guarded(next->ProcessId))
					{
						if (!next->NextEntryOffset) { current->NextEntryOffset = 0; }
						else { current->NextEntryOffset += next->NextEntryOffset; }

						next = current;
					}
				} while (current->NextEntryOffset != 0);
			}

			return status;
		}));

		hook::hook_ssdt("NtTerminateProcess", static_cast<NTSTATUS(*)(HANDLE, NTSTATUS)>([](HANDLE ProcessHandle, NTSTATUS ExitStatus)
		{
			if (ProcessHandle)
			{
				PEPROCESS process{};
				if (NT_SUCCESS(ObReferenceObjectByHandle(ProcessHandle, PROCESS_ALL_ACCESS, *PsProcessType, MODE::KernelMode, reinterpret_cast<void**>(&process)
					, nullptr)))
				{
					auto process_id = PsGetProcessId(process);
					ObDereferenceObject(process);
					if (require(process_id, guard_level::strict)) { return STATUS_ACCESS_DENIED; }
				}
			}

			static NTSTATUS(*NtTerminateProcess)(HANDLE, NTSTATUS)
			{
				static_cast<NTSTATUS(*)(HANDLE, NTSTATUS)>(ext::get_ssdt_entry(ssdt::get_ssdt_index("NtTerminateProcess")))
			};

			return NtTerminateProcess(ProcessHandle, ExitStatus);
		}));

		hook::hook_ssdt("NtDebugActiveProcess", static_cast<NTSTATUS(*)(HANDLE, HANDLE)>([](HANDLE ProcessHandle, HANDLE DebugObjectHandle)
		{
			if (ProcessHandle)
			{
				PEPROCESS process{};
				if (NT_SUCCESS(ObReferenceObjectByHandle(ProcessHandle, PROCESS_ALL_ACCESS, *PsProcessType, MODE::KernelMode, reinterpret_cast<void**>(&process)
					, nullptr)))
				{
					auto process_id = PsGetProcessId(process);
					ObDereferenceObject(process);
					if (require(process_id, guard_level::highest)) return STATUS_ACCESS_DENIED;
				}
			}

			static auto NtDebugActiveProcess{ static_cast<NTSTATUS(*)(HANDLE, HANDLE)>(ext::get_ssdt_entry(ssdt::get_ssdt_index("NtDebugActiveProcess"))) };
			return NtDebugActiveProcess(ProcessHandle, DebugObjectHandle);
		}));

		hook::hook_ssdt("NtDebugContinue", static_cast<NTSTATUS(*)(HANDLE, PCLIENT_ID, NTSTATUS)>([](HANDLE DebugHandle, PCLIENT_ID AppClientId,
			NTSTATUS ContinueStatus)
		{
			if (require(AppClientId->UniqueProcess, guard_level::highest)) return STATUS_ACCESS_DENIED;

			static auto NtDebugContinue{ static_cast<NTSTATUS(*)(HANDLE, PCLIENT_ID, NTSTATUS)>(ext::get_ssdt_entry(ssdt::get_ssdt_index("NtDebugContinue"))) };
			return NtDebugContinue(DebugHandle, AppClientId, ContinueStatus);
		}));

		hook::hook_ssdt("NtCreateThread", static_cast<NTSTATUS(*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PCLIENT_ID, PCONTEXT, void*, BOOLEAN)>(
			[](PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
				HANDLE ProcessHandle, PCLIENT_ID ClientId, PCONTEXT ThreadContext, void* InitialTeb, BOOLEAN CreateSuspended)
		{

			if (ProcessHandle)
			{
				PEPROCESS process{};
				if (NT_SUCCESS(ObReferenceObjectByHandle(ProcessHandle, PROCESS_ALL_ACCESS, *PsProcessType, MODE::KernelMode, reinterpret_cast<void**>(&process)
					, nullptr)))
				{
					auto process_id = PsGetProcessId(process);
					ObDereferenceObject(process);
					if (require(process_id, guard_level::highest)) return STATUS_ACCESS_DENIED;
				}
			}

			static auto NtCreateThread{ static_cast<NTSTATUS(*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PCLIENT_ID, PCONTEXT, void*, BOOLEAN)>(
					ext::get_ssdt_entry(ssdt::get_ssdt_index("NtCreateThread"))) };
			return NtCreateThread(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, ClientId, ThreadContext, InitialTeb, CreateSuspended);
		}));

		hook::hook_ssdt("NtSuspendThread", static_cast<NTSTATUS(*)(HANDLE, PULONG)>([](HANDLE ThreadHandle, PULONG PreviousSuspendCount)
		{
			if (ThreadHandle)
			{
				PETHREAD thread{};
				if (NT_SUCCESS(ObReferenceObjectByHandle(ThreadHandle, THREAD_ALL_ACCESS, *PsThreadType, MODE::KernelMode, reinterpret_cast<void**>(&thread)
					, nullptr)))
				{
					if (require(PsGetProcessId(IoThreadToProcess(thread)), guard_level::basic)) return STATUS_ACCESS_DENIED;
				}
			}

			static auto NtSuspendThread{ static_cast<NTSTATUS(*)(HANDLE, PULONG)>(ext::get_ssdt_entry(ssdt::get_ssdt_index("NtSuspendThread"))) };
			return NtSuspendThread(ThreadHandle, PreviousSuspendCount);
		}));

		hook::hook_ssdt("NtQueueApcThread", static_cast<NTSTATUS(*)(HANDLE, PKNORMAL_ROUTINE, PVOID, PVOID, PVOID)>(
			[](HANDLE ThreadHandle, PKNORMAL_ROUTINE ApcRoutine, PVOID ApcContext, PVOID Argument1, PVOID Argument2)
		{
			if (ThreadHandle)
			{
				PETHREAD thread{};
				if (NT_SUCCESS(ObReferenceObjectByHandle(ThreadHandle, THREAD_ALL_ACCESS, *PsThreadType, MODE::KernelMode, reinterpret_cast<void**>(&thread)
					, nullptr)))
				{
					if (require(PsGetProcessId(IoThreadToProcess(thread)), guard_level::highest)) return STATUS_ACCESS_DENIED;
				}
			}

			static auto NtQueueApcThread{ static_cast<NTSTATUS(*)(HANDLE, PKNORMAL_ROUTINE, PVOID, PVOID, PVOID)>(
				ext::get_ssdt_entry(ssdt::get_ssdt_index("NtQueueApcThread"))) };
			return NtQueueApcThread(ThreadHandle, ApcRoutine, ApcContext, Argument1, Argument2);
		}));

		hook::hook_ssdt("NtAllocateVirtualMemory", static_cast<NTSTATUS(*)(HANDLE, PVOID*, ULONG, PULONG, ULONG, ULONG)>(
			[](HANDLE ProcessHandle, PVOID* BaseAddress, ULONG ZeroBits, PULONG AllocationSize, ULONG AllocationType, ULONG Protect)
		{
			if (ProcessHandle)
			{
				PEPROCESS process{};
				if (NT_SUCCESS(ObReferenceObjectByHandle(ProcessHandle, PROCESS_ALL_ACCESS, *PsProcessType, MODE::KernelMode, reinterpret_cast<void**>(&process)
					, nullptr)))
				{
					auto process_id = PsGetProcessId(process);
					ObDereferenceObject(process);
					if (require(process_id, guard_level::highest)) return STATUS_ACCESS_DENIED;
				}
			}

			static auto NtAllocateVirtualMemory{ static_cast<NTSTATUS(*)(HANDLE, PVOID*,ULONG,PULONG, ULONG, ULONG)> (
				ext::get_ssdt_entry(ssdt::get_ssdt_index("NtAllocateVirtualMemory"))) };
			return NtAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits, AllocationSize, AllocationType, Protect);
		}));

		hook::hook_ssdt("NtDuplicateObject", static_cast<NTSTATUS(*)(HANDLE, HANDLE, HANDLE, PHANDLE, ACCESS_MASK, ULONG, ULONG)>(
			[](HANDLE SourceProcessHandle, HANDLE SourceHandle, HANDLE TargetProcessHandle, PHANDLE TargetHandle, ACCESS_MASK DesiredAccess,
				ULONG Attributes, ULONG Options)
		{
			if (SourceProcessHandle)
			{
				PEPROCESS process{};
				if (NT_SUCCESS(ObReferenceObjectByHandle(SourceProcessHandle, PROCESS_ALL_ACCESS, *PsProcessType, MODE::KernelMode,
					reinterpret_cast<void**>(&process), nullptr)))
				{
					auto process_id = PsGetProcessId(process);
					ObDereferenceObject(process);
					if (require(process_id, guard_level::highest)) { return STATUS_ACCESS_DENIED; }
				}
			}

			static auto NtDuplicateObject{ static_cast<NTSTATUS(*)(HANDLE, HANDLE, HANDLE, PHANDLE, ACCESS_MASK, ULONG, ULONG)>(
				ext::get_ssdt_entry(ssdt::get_ssdt_index("NtDuplicateObject"))) };

			return NtDuplicateObject(SourceProcessHandle, SourceHandle, TargetProcessHandle, TargetHandle, DesiredAccess, Attributes, Options);
		}));

		hook::hook_ssdt("NtGetContextThread", static_cast<NTSTATUS(*)(HANDLE, PCONTEXT)>([](HANDLE ThreadHandle, PCONTEXT Context)
		{
			if (ThreadHandle)
			{
				PETHREAD thread{};
				if (NT_SUCCESS(ObReferenceObjectByHandle(ThreadHandle, THREAD_ALL_ACCESS, *PsThreadType, MODE::KernelMode, reinterpret_cast<void**>(&thread)
					, nullptr)))
				{
					if (require(PsGetProcessId(IoThreadToProcess(thread)), guard_level::highest)) return STATUS_ACCESS_DENIED;
				}
			}

			static auto NtGetContextThread{ static_cast<NTSTATUS(*)(HANDLE, PCONTEXT)>(ext::get_ssdt_entry(ssdt::get_ssdt_index("NtGetContextThread"))) };
			return NtGetContextThread(ThreadHandle, Context);
		}));

		hook::hook_ssdt("NtSetContextThread", static_cast<NTSTATUS(*)(HANDLE, PCONTEXT)>([](HANDLE ThreadHandle, PCONTEXT Context)
		{
			if (ThreadHandle)
			{
				PETHREAD thread{};
				if (NT_SUCCESS(ObReferenceObjectByHandle(ThreadHandle, THREAD_ALL_ACCESS, *PsThreadType, MODE::KernelMode, reinterpret_cast<void**>(&thread)
					, nullptr)))
				{
					if (require(PsGetProcessId(IoThreadToProcess(thread)), guard_level::highest)) return STATUS_ACCESS_DENIED;
				}
			}

			static auto NtSetContextThread{ static_cast<NTSTATUS(*)(HANDLE, PCONTEXT)>(ext::get_ssdt_entry(ssdt::get_ssdt_index("NtSetContextThread"))) };
			return NtSetContextThread(ThreadHandle, Context);
		}));

		hook::hook_ssdt("NtQueryInformationProcess", static_cast<NTSTATUS(*)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG)>(
			[](HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength)
		{
			if (ProcessHandle)
			{
				PEPROCESS process{};
				if (NT_SUCCESS(ObReferenceObjectByHandle(ProcessHandle, PROCESS_ALL_ACCESS, *PsProcessType, MODE::KernelMode, reinterpret_cast<void**>(&process)
					, nullptr)))
				{
					auto process_id = PsGetProcessId(process);
					ObDereferenceObject(process);
					if (require(process_id, guard_level::highest)) { return STATUS_ACCESS_DENIED; }
				}
			}

			static auto NtQueryInformationProcess{ static_cast<NTSTATUS(*)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG)>(
				ext::get_ssdt_entry(ssdt::get_ssdt_index("NtQueryInformationProcess"))) };
			return NtQueryInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
		}));

		hook::hook_ssdt("NtSetInformationProcess", static_cast<NTSTATUS(*)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG)>(
			[](HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength)
		{
			if (ProcessHandle)
			{
				PEPROCESS process{};
				if (NT_SUCCESS(ObReferenceObjectByHandle(ProcessHandle, PROCESS_ALL_ACCESS, *PsProcessType, MODE::KernelMode, reinterpret_cast<void**>(&process)
					, nullptr)))
				{
					auto process_id = PsGetProcessId(process);
					ObDereferenceObject(process);
					if (require(process_id, guard_level::highest)) { return STATUS_ACCESS_DENIED; }
				}
			}

			static auto NtSetInformationProcess{ static_cast<NTSTATUS(*)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG)>(
				ext::get_ssdt_entry(ssdt::get_ssdt_index("NtSetInformationProcess"))) };
			return NtSetInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength);
		}));

		hook::hook_ssdt("NtSetInformationThread", static_cast<NTSTATUS(*)(HANDLE, THREADINFOCLASS, PVOID, ULONG)>(
			[](HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength)
		{
			if (ThreadHandle)
			{
				PETHREAD thread{};
				if (NT_SUCCESS(ObReferenceObjectByHandle(ThreadHandle, THREAD_ALL_ACCESS, *PsThreadType, MODE::KernelMode, reinterpret_cast<void**>(&thread)
					, nullptr)))
				{
					if (require(PsGetProcessId(IoThreadToProcess(thread)), guard_level::highest)) { return STATUS_ACCESS_DENIED; }
				}
			}

			static auto NtSetInformationThread{ static_cast<NTSTATUS(*)(HANDLE, THREADINFOCLASS, PVOID, ULONG)>(
				ext::get_ssdt_entry(ssdt::get_ssdt_index("NtSetInformationThread"))) };
			return NtSetInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength);
		}));

		hook::hook_ssdt("NtQueryInformationThread", static_cast<NTSTATUS(*)(HANDLE, THREADINFOCLASS, PVOID, ULONG, PULONG)>(
			[](HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength, PULONG ReturnLength)
		{
			if (ThreadHandle)
			{
				PETHREAD thread{};
				if (NT_SUCCESS(ObReferenceObjectByHandle(ThreadHandle, THREAD_ALL_ACCESS, *PsThreadType, MODE::KernelMode, reinterpret_cast<void**>(&thread)
					, nullptr)))
				{
					if (require(PsGetProcessId(IoThreadToProcess(thread)), guard_level::highest)) { return STATUS_ACCESS_DENIED; }
				}
			}

			static auto NtQueryInformationThread{ static_cast<NTSTATUS(*)(HANDLE, THREADINFOCLASS, PVOID, ULONG, PULONG)>(
				ext::get_ssdt_entry(ssdt::get_ssdt_index("NtQueryInformationThread"))) };
			return NtQueryInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength, ReturnLength);
		}));

		hook::hook_ssdt("NtFreeVirtualMemory", static_cast<NTSTATUS(*)(HANDLE, PVOID*, PULONG, ULONG)>(
			[](HANDLE ProcessHandle, PVOID* BaseAddress, PULONG FreeSize, ULONG FreeType)
		{
			if (ProcessHandle)
			{
				PEPROCESS process{};
				if (NT_SUCCESS(ObReferenceObjectByHandle(ProcessHandle, PROCESS_ALL_ACCESS, *PsProcessType, MODE::KernelMode, reinterpret_cast<void**>(&process)
					, nullptr)))
				{
					auto process_id = PsGetProcessId(process);
					ObDereferenceObject(process);
					if (require(process_id, guard_level::highest)) return STATUS_ACCESS_DENIED;
				}
			}

			static auto NtFreeVirtualMemory{ static_cast<NTSTATUS(*)(HANDLE, PVOID*, PULONG, ULONG)> (
				ext::get_ssdt_entry(ssdt::get_ssdt_index("NtFreeVirtualMemory"))) };
			return NtFreeVirtualMemory(ProcessHandle, BaseAddress, FreeSize, FreeType);
		}));

		hook::hook_ssdt("NtProtectVirtualMemory", static_cast<NTSTATUS(*)(HANDLE, PVOID*, PULONG, ULONG, PULONG)>(
			[](HANDLE ProcessHandle, PVOID* BaseAddress, PULONG ProtectSize, ULONG NewProtect, PULONG OldProtect)
		{
			if (ProcessHandle)
			{
				PEPROCESS process{};
				if (NT_SUCCESS(ObReferenceObjectByHandle(ProcessHandle, PROCESS_ALL_ACCESS, *PsProcessType, MODE::KernelMode, reinterpret_cast<void**>(&process)
					, nullptr)))
				{
					auto process_id = PsGetProcessId(process);
					ObDereferenceObject(process);
					if (require(process_id, guard_level::highest)) return STATUS_ACCESS_DENIED;
				}
			}

			static auto NtProtectVirtualMemory{ static_cast<NTSTATUS(*)(HANDLE, PVOID*, PULONG, ULONG, PULONG)> (
				ext::get_ssdt_entry(ssdt::get_ssdt_index("NtProtectVirtualMemory"))) };
			return NtProtectVirtualMemory(ProcessHandle, BaseAddress, ProtectSize, NewProtect, OldProtect);
		}));

		hook::hook_ssdt("NtLockVirtualMemory", static_cast<NTSTATUS(*)(HANDLE, PVOID*, PULONG, ULONG)>(
			[](HANDLE ProcessHandle, PVOID* BaseAddress, PULONG LockSize, ULONG LockType)
		{
			if (ProcessHandle)
			{
				PEPROCESS process{};
				if (NT_SUCCESS(ObReferenceObjectByHandle(ProcessHandle, PROCESS_ALL_ACCESS, *PsProcessType, MODE::KernelMode, reinterpret_cast<void**>(&process)
					, nullptr)))
				{
					auto process_id = PsGetProcessId(process);
					ObDereferenceObject(process);
					if (require(process_id, guard_level::highest)) return STATUS_ACCESS_DENIED;
				}
			}

			static auto NtLockVirtualMemory{ static_cast<NTSTATUS(*)(HANDLE, PVOID*, PULONG, ULONG)> (
				ext::get_ssdt_entry(ssdt::get_ssdt_index("NtLockVirtualMemory"))) };
			return NtLockVirtualMemory(ProcessHandle, BaseAddress, LockSize, LockType);
		}));

		hook::hook_ssdt("NtUnlockVirtualMemory", static_cast<NTSTATUS(*)(HANDLE, PVOID*, PULONG, ULONG)>(
			[](HANDLE ProcessHandle, PVOID* BaseAddress, PULONG LockSize, ULONG LockType)
		{
			if (ProcessHandle)
			{
				PEPROCESS process{};
				if (NT_SUCCESS(ObReferenceObjectByHandle(ProcessHandle, PROCESS_ALL_ACCESS, *PsProcessType, MODE::KernelMode, reinterpret_cast<void**>(&process)
					, nullptr)))
				{
					auto process_id = PsGetProcessId(process);
					ObDereferenceObject(process);
					if (require(process_id, guard_level::highest)) return STATUS_ACCESS_DENIED;
				}
			}

			static auto NtUnlockVirtualMemory{ static_cast<NTSTATUS(*)(HANDLE, PVOID*, PULONG, ULONG)> (
				ext::get_ssdt_entry(ssdt::get_ssdt_index("NtUnlockVirtualMemory"))) };
			return NtUnlockVirtualMemory(ProcessHandle, BaseAddress, LockSize, LockType);
		}));

		hook::hook_ssdt("NtReadVirtualMemory", static_cast<NTSTATUS(*)(HANDLE, PVOID, PVOID, ULONG, PULONG)>(
			[](HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG BufferLength, PULONG ReturnLength)
		{
			if (ProcessHandle)
			{
				PEPROCESS process{};
				if (NT_SUCCESS(ObReferenceObjectByHandle(ProcessHandle, PROCESS_ALL_ACCESS, *PsProcessType, MODE::KernelMode, reinterpret_cast<void**>(&process)
					, nullptr)))
				{
					auto process_id = PsGetProcessId(process);
					ObDereferenceObject(process);
					if (require(process_id, guard_level::highest)) return STATUS_ACCESS_DENIED;
				}
			}

			static auto NtReadVirtualMemory{ static_cast<NTSTATUS(*)(HANDLE, PVOID, PVOID, ULONG, PULONG)> (
				ext::get_ssdt_entry(ssdt::get_ssdt_index("NtReadVirtualMemory"))) };
			return NtReadVirtualMemory(ProcessHandle, BaseAddress, Buffer, BufferLength, ReturnLength);
		}));

		hook::hook_ssdt("NtWriteVirtualMemory", static_cast<NTSTATUS(*)(HANDLE, PVOID, PVOID, ULONG, PULONG)>(
			[](HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG BufferLength, PULONG ReturnLength)
		{
			if (ProcessHandle)
			{
				PEPROCESS process{};
				if (NT_SUCCESS(ObReferenceObjectByHandle(ProcessHandle, PROCESS_ALL_ACCESS, *PsProcessType, MODE::KernelMode, reinterpret_cast<void**>(&process)
					, nullptr)))
				{
					auto process_id = PsGetProcessId(process);
					ObDereferenceObject(process);
					if (require(process_id, guard_level::highest)) return STATUS_ACCESS_DENIED;
				}
			}

			static auto NtWriteVirtualMemory{ static_cast<NTSTATUS(*)(HANDLE, PVOID, PVOID, ULONG, PULONG)> (
				ext::get_ssdt_entry(ssdt::get_ssdt_index("NtWriteVirtualMemory"))) };
			return NtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, BufferLength, ReturnLength);
		}));

		hook::hook_ssdt("NtFlushVirtualMemory", static_cast<NTSTATUS(*)(HANDLE, PVOID*, PULONG, PIO_STATUS_BLOCK)>(
			[](HANDLE ProcessHandle, PVOID* BaseAddress, PULONG FlushSize, PIO_STATUS_BLOCK IoStatusBlock)
		{
			if (ProcessHandle)
			{
				PEPROCESS process{};
				if (NT_SUCCESS(ObReferenceObjectByHandle(ProcessHandle, PROCESS_ALL_ACCESS, *PsProcessType, MODE::KernelMode, reinterpret_cast<void**>(&process)
					, nullptr)))
				{
					auto process_id = PsGetProcessId(process);
					ObDereferenceObject(process);
					if (require(process_id, guard_level::highest)) return STATUS_ACCESS_DENIED;
				}
			}

			static auto NtFlushVirtualMemory{ static_cast<NTSTATUS(*)(HANDLE, PVOID*, PULONG, PIO_STATUS_BLOCK)> (
				ext::get_ssdt_entry(ssdt::get_ssdt_index("NtFlushVirtualMemory"))) };
			return NtFlushVirtualMemory(ProcessHandle, BaseAddress, FlushSize, IoStatusBlock);
		}));

		#pragma endregion

		// Inline hook disabled.
		#ifdef INLINE_HOOK

		inline_hook::hook(NtOpenProcess, static_cast<decltype(&NtOpenProcess)>([](PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess,
			POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId)
		{
			if (MmIsAddressValid(ClientId) && is_protected(ClientId->UniqueProcess))
			{
				return STATUS_ACCESS_DENIED;
			}

			return static_cast<decltype(&NtOpenProcess)>(inline_hook::get_unhooked(NtOpenProcess))(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
		}));

		inline_hook::hook(ZwOpenProcess, static_cast<decltype(&ZwOpenProcess)>([](PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess,
			POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId)
		{
			if (MmIsAddressValid(ClientId) && is_protected(ClientId->UniqueProcess))
			{
				return STATUS_ACCESS_DENIED;
			}

			return static_cast<decltype(&ZwOpenProcess)>(inline_hook::get_unhooked(ZwOpenProcess))(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
		}));

		inline_hook::hook(ZwTerminateProcess, static_cast<decltype(&ZwTerminateProcess)>([](HANDLE ProcessHandle, NTSTATUS ExitStatus)
		{
			PEPROCESS process{};
			auto status{ process::handle_to_process(ProcessHandle, process) };
			if (!NT_SUCCESS(status)) { return status; }
			if (is_protected(PsGetProcessId(process))) { return STATUS_ACCESS_DENIED; }
			return static_cast<decltype(&ZwTerminateProcess)>(inline_hook::get_unhooked(ZwTerminateProcess))(ProcessHandle, ExitStatus);
		}));

		inline_hook::hook(L"NtTerminateProcess"e, static_cast<decltype(&ZwTerminateProcess)>([](HANDLE ProcessHandle, NTSTATUS ExitStatus)
		{
			PEPROCESS process{};
			auto status{ process::handle_to_process(ProcessHandle, process) };
			if (!NT_SUCCESS(status)) { return status; }
			if (is_protected(PsGetProcessId(process))) { return STATUS_ACCESS_DENIED; }
			return static_cast<decltype(&ZwTerminateProcess)>(inline_hook::get_unhooked(L"NtTerminateProcess"e))(ProcessHandle, ExitStatus);
		}));

		inline_hook::hook(PsLookupProcessByProcessId, static_cast<decltype(&PsLookupProcessByProcessId)>([](HANDLE ProcessId, PEPROCESS* Process)
		{
			if (is_protected(ProcessId)) { return STATUS_ACCESS_DENIED; }
			return static_cast<decltype(&PsLookupProcessByProcessId)>(inline_hook::get_unhooked(PsLookupProcessByProcessId))(ProcessId, Process);
		}));

		inline_hook::hook(ObOpenObjectByPointer, static_cast<decltype(&ObOpenObjectByPointer)>([](PVOID Object, ULONG HandleAttributes,
			PACCESS_STATE PassedAccessState, ACCESS_MASK DesiredAccess, POBJECT_TYPE ObjectType, KPROCESSOR_MODE AccessMode, PHANDLE Handle)
		{
			if (ObjectType == *PsProcessType && is_protected(PsGetProcessId(reinterpret_cast<PEPROCESS>(Object))))
			{
				return STATUS_ACCESS_DENIED;
			}

			return static_cast<decltype(&ObOpenObjectByPointer)>(inline_hook::get_unhooked(ObOpenObjectByPointer))(Object, HandleAttributes, PassedAccessState,
				DesiredAccess, ObjectType, AccessMode, Handle);
		}));

		inline_hook::hook(ObReferenceObjectByHandle, static_cast<decltype(&ObReferenceObjectByHandle)>([](HANDLE Handle, ACCESS_MASK DesiredAccess,
			POBJECT_TYPE ObjectType, KPROCESSOR_MODE AccessMode, PVOID* Object, POBJECT_HANDLE_INFORMATION HandleInformation)
		{
			if (ObjectType)
			{
				if (ObjectType == *PsProcessType)
				{
					PEPROCESS process{};
					if (NT_SUCCESS(static_cast<decltype(&ObReferenceObjectByHandle)>(inline_hook::get_unhooked(ObReferenceObjectByHandle))(Handle, PROCESS_ALL_ACCESS,
						*PsProcessType, MODE::KernelMode, reinterpret_cast<void**>(&process), nullptr)) && is_protected(PsGetProcessId(process)))
					{
						return STATUS_ACCESS_DENIED;
					}
				}
				else if (ObjectType == *PsThreadType)
				{
					PETHREAD thread{};
					if (NT_SUCCESS(static_cast<decltype(&ObReferenceObjectByHandle)>(inline_hook::get_unhooked(ObReferenceObjectByHandle))(Handle, PROCESS_ALL_ACCESS,
						*PsThreadType, MODE::KernelMode, reinterpret_cast<void**>(&thread), nullptr)) && is_protected(PsGetProcessId(IoThreadToProcess(thread))))
					{
						return STATUS_ACCESS_DENIED;
					}
				}
			}

			return static_cast<decltype(&ObReferenceObjectByHandle)>(inline_hook::get_unhooked(ObReferenceObjectByHandle))(Handle, DesiredAccess, ObjectType,
				AccessMode, Object, HandleInformation);
		}));

		inline_hook::hook(PsLookupThreadByThreadId, static_cast<decltype(&PsLookupThreadByThreadId)>([](HANDLE ThreadId, PETHREAD* Thread)
		{
			HANDLE thread_handle{};
			PETHREAD thread{};
			if (NT_SUCCESS(thread::open_thread_by_id(ThreadId, thread_handle)) &&
				static_cast<decltype(&ObReferenceObjectByHandle)>(inline_hook::get_unhooked(ObReferenceObjectByHandle))(thread_handle, THREAD_ALERT, *PsThreadType,
					MODE::KernelMode, reinterpret_cast<void**>(thread), nullptr) && is_protected(PsGetProcessId(thread::thread_to_process(thread))))
			{
				return STATUS_ACCESS_DENIED;
			}

			return static_cast<decltype(&PsLookupThreadByThreadId)>(inline_hook::get_unhooked(PsLookupThreadByThreadId))(ThreadId, Thread);
		}));
		#endif
	}
}