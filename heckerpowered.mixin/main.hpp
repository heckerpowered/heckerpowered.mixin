#pragma once
#include <ntifs.h>
#include "object_callback.hpp"
#include "communication.hpp"
#include "process_callback.hpp"
#include "compatibility.hpp"
#include "handle.hpp"
#include "headers.hpp"
#include "infinity_hook.hpp"
#include "inline_hook.hpp"
#include "module.hpp"
#include "patch_guard.hpp"
#include "image_callback.hpp"
#include "system.hpp"
#include "concurrent.hpp"
#include "string_literal.hpp"

extern "C" DRIVER_INITIALIZE DriverEntry;

typedef struct _LDR_DATA_TABLE_ENTRY64
{
	LIST_ENTRY64    InLoadOrderLinks;
	LIST_ENTRY64    InMemoryOrderLinks;
	LIST_ENTRY64    InInitializationOrderLinks;
	PVOID            DllBase;
	PVOID            EntryPoint;
	ULONG            SizeOfImage;
	UNICODE_STRING    FullDllName;
	UNICODE_STRING     BaseDllName;
	ULONG            Flags;
	USHORT            LoadCount;
	USHORT            TlsIndex;
	PVOID            SectionPointer;
	ULONG            CheckSum;
	PVOID            LoadedImports;
	PVOID            EntryPointActivationContext;
	PVOID            PatchInformation;
	LIST_ENTRY64    ForwarderLinks;
	LIST_ENTRY64    ServiceTagLinks;
	LIST_ENTRY64    StaticLinks;
	PVOID            ContextInformation;
	ULONG64            OriginalBase;
	LARGE_INTEGER    LoadTime;
}*PLDR_DATA_TABLE_ENTRY64;

namespace mixin
{
	extern struct _DRIVER_OBJECT* driver_object;
}