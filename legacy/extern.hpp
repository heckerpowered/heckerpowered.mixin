#pragma once

extern "C" {
    typedef struct _CPUID
    {
        int eax;
        int ebx;
        int ecx;
        int edx;
    } CPUID, * PCPUID;

    typedef struct _NT_KPROCESS
    {
        DISPATCHER_HEADER Header;
        LIST_ENTRY        ProfileListHead;
        ULONG_PTR         DirectoryTableBase;
        UCHAR             Data[1];
    } NT_KPROCESS, * PNT_KPROCESS;

    char* NTAPI
        PsGetProcessImageFileName(
            __in PEPROCESS Process
        );

    NTSYSAPI
        NTSTATUS
        NTAPI
        ZwQuerySystemInformation(
            IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
            OUT PVOID SystemInformation,
            IN ULONG SystemInformationLength,
            OUT PULONG ReturnLength OPTIONAL
        );

    NTSYSAPI
        NTSTATUS
        NTAPI
        ZwSetSystemInformation(
            IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
            IN PVOID SystemInformation,
            IN ULONG SystemInformationLength
        );

    NTSYSAPI
        NTSTATUS
        NTAPI
        ZwQueryInformationProcess(
            IN  HANDLE ProcessHandle,
            IN  PROCESSINFOCLASS ProcessInformationClass,
            OUT PVOID ProcessInformation,
            IN  ULONG ProcessInformationLength,
            IN  PULONG ReturnLength
        );

    NTSYSAPI
        NTSTATUS
        NTAPI
        ZwQueryInformationThread(
            IN HANDLE ThreadHandle,
            IN THREADINFOCLASS ThreadInformationClass,
            OUT PVOID ThreadInformation,
            IN ULONG ThreadInformationLength,
            OUT PULONG ReturnLength OPTIONAL
        );

    #if !__has_include(<ntifs.h>)

    NTSYSAPI
        NTSTATUS
        NTAPI
        ZwQueryVirtualMemory(
            IN HANDLE  ProcessHandle,
            IN PVOID   BaseAddress,
            IN MEMORY_INFORMATION_CLASS_EX MemoryInformationClass,
            OUT PVOID  Buffer,
            IN SIZE_T  Length,
            OUT PSIZE_T ResultLength
        );
    #endif
    NTSTATUS
        NTAPI
        ZwCreateThreadEx(
            OUT PHANDLE hThread,
            IN ACCESS_MASK DesiredAccess,
            IN PVOID ObjectAttributes,
            IN HANDLE ProcessHandle,
            IN PVOID lpStartAddress,
            IN PVOID lpParameter,
            IN ULONG Flags,
            IN SIZE_T StackZeroBits,
            IN SIZE_T SizeOfStackCommit,
            IN SIZE_T SizeOfStackReserve,
            IN PNT_PROC_THREAD_ATTRIBUTE_LIST AttributeList
        );

    NTSTATUS
        NTAPI
        ZwTerminateThread(
            IN HANDLE ThreadHandle,
            IN NTSTATUS ExitStatus
        );

    NTKERNELAPI
        NTSTATUS
        NTAPI
        MmCopyVirtualMemory(
            IN PEPROCESS FromProcess,
            IN PVOID FromAddress,
            IN PEPROCESS ToProcess,
            OUT PVOID ToAddress,
            IN SIZE_T BufferSize,
            IN KPROCESSOR_MODE PreviousMode,
            OUT PSIZE_T NumberOfBytesCopied
        );

    NTKERNELAPI
        PPEB
        NTAPI
        PsGetProcessPeb(IN PEPROCESS Process);

    NTKERNELAPI
        PVOID
        NTAPI
        PsGetThreadTeb(IN PETHREAD Thread);

    NTKERNELAPI
        PVOID
        NTAPI
        PsGetProcessWow64Process(IN PEPROCESS Process);

    NTKERNELAPI
        PVOID
        NTAPI
        PsGetCurrentProcessWow64Process();

    NTKERNELAPI
        BOOLEAN
        NTAPI
        KeTestAlertThread(IN KPROCESSOR_MODE AlertMode);

    NTKERNELAPI
        BOOLEAN
        NTAPI
        PsIsProtectedProcess(IN PEPROCESS Process);

    typedef VOID(NTAPI* PKNORMAL_ROUTINE)(
        PVOID NormalContext,
        PVOID SystemArgument1,
        PVOID SystemArgument2
        );

    typedef VOID(NTAPI* PKKERNEL_ROUTINE)(
        PRKAPC Apc,
        PKNORMAL_ROUTINE* NormalRoutine,
        PVOID* NormalContext,
        PVOID* SystemArgument1,
        PVOID* SystemArgument2
        );

    typedef VOID(NTAPI* PKRUNDOWN_ROUTINE)(PRKAPC Apc);

    NTKERNELAPI
        VOID
        NTAPI
        KeInitializeApc(
            IN PKAPC Apc,
            IN PKTHREAD Thread,
            IN KAPC_ENVIRONMENT ApcStateIndex,
            IN PKKERNEL_ROUTINE KernelRoutine,
            IN PKRUNDOWN_ROUTINE RundownRoutine,
            IN PKNORMAL_ROUTINE NormalRoutine,
            IN KPROCESSOR_MODE ApcMode,
            IN PVOID NormalContext
        );

    NTKERNELAPI
        BOOLEAN
        NTAPI
        KeInsertQueueApc(
            PKAPC Apc,
            PVOID SystemArgument1,
            PVOID SystemArgument2,
            KPRIORITY Increment
        );

    NTSYSAPI
        PIMAGE_NT_HEADERS
        NTAPI
        RtlImageNtHeader(PVOID Base);

    NTSYSAPI
        PVOID
        NTAPI
        RtlImageDirectoryEntryToData(
            PVOID ImageBase,
            BOOLEAN MappedAsImage,
            USHORT DirectoryEntry,
            PULONG Size
        );

    typedef BOOLEAN(*EX_ENUMERATE_HANDLE_ROUTINE)(
        #if !defined(_WIN7_)
        IN PHANDLE_TABLE HandleTable,
        #endif
        IN PHANDLE_TABLE_ENTRY HandleTableEntry,
        IN HANDLE Handle,
        IN PVOID EnumParameter
        );

    NTKERNELAPI
        BOOLEAN
        ExEnumHandleTable(
            IN PHANDLE_TABLE HandleTable,
            IN EX_ENUMERATE_HANDLE_ROUTINE EnumHandleProcedure,
            IN PVOID EnumParameter,
            OUT PHANDLE Handle
        );

    NTKERNELAPI
        VOID
        FASTCALL
        ExfUnblockPushLock(
            IN OUT PEX_PUSH_LOCK PushLock,
            IN OUT PVOID WaitBlock
        );

    ULONG
        NTAPI
        KeCapturePersistentThreadState(
            IN PCONTEXT Context,
            IN PKTHREAD Thread,
            IN ULONG BugCheckCode,
            IN ULONG BugCheckParameter1,
            IN ULONG BugCheckParameter2,
            IN ULONG BugCheckParameter3,
            IN ULONG BugCheckParameter4,
            OUT PVOID VirtualAddress
        );

    NTKERNELAPI
        _IRQL_requires_max_(APC_LEVEL)
        _IRQL_requires_min_(PASSIVE_LEVEL)
        _IRQL_requires_same_
        VOID
        KeGenericCallDpc(
            _In_ PKDEFERRED_ROUTINE Routine,
            _In_opt_ PVOID          Context);

    NTKERNELAPI
        _IRQL_requires_(DISPATCH_LEVEL)
        _IRQL_requires_same_
        VOID
        KeSignalCallDpcDone(
            _In_ PVOID SystemArgument1);

    NTKERNELAPI
        _IRQL_requires_(DISPATCH_LEVEL)
        _IRQL_requires_same_
        LOGICAL
        KeSignalCallDpcSynchronize(
            _In_ PVOID SystemArgument2);
}
extern unsigned long kernel_base_size;

namespace ext {
    void* get_kernel_base(unsigned long& size) noexcept;
    void* get_ssdt_entry(unsigned long index);
    void* get_kernel_base() noexcept;
}