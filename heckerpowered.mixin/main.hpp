#pragma once
#include <ntddk.h>
#include "device.hpp"

_Use_decl_annotations_ extern "C" DRIVER_INITIALIZE DriverEntry;
_Use_decl_annotations_ extern "C" DRIVER_UNLOAD DriverUnload;

_Function_class_(DRIVER_DISPATCH)
_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_requires_same_
_Dispatch_type_(IRP_MJ_CREATE)
_Dispatch_type_(IRP_MJ_CLOSE)
NTSTATUS DefaultDispatcher(struct _DEVICE_OBJECT* device_object [[maybe_unused]], struct _IRP* irp) noexcept;

#if defined(ALLOC_PRAGMA)
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(INIT, DriverUnload)
#endif

_Struct_size_bytes_(224)
typedef struct _LDR_DATA_TABLE_ENTRY64
{
	LIST_ENTRY64 InLoadOrderLinks;
	LIST_ENTRY64 InMemoryOrderLinks;
	LIST_ENTRY64 InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	PVOID SectionPointer;
	ULONG CheckSum;
	PVOID LoadedImports;
	PVOID EntryPointActivationContext;
	PVOID PatchInformation;
	LIST_ENTRY64 ForwarderLinks;
	LIST_ENTRY64 ServiceTagLinks;
	LIST_ENTRY64 StaticLinks;
	PVOID ContextInformation;
	ULONG64 OriginalBase;
	LARGE_INTEGER LoadTime;
}*PLDR_DATA_TABLE_ENTRY64;

static_assert(sizeof(_LDR_DATA_TABLE_ENTRY64) == 224);