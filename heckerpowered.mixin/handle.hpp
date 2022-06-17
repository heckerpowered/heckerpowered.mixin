#pragma once

#define INVALID_HANDLE_VALUE ((HANDLE)(LONG_PTR)-1)
#define KERNEL_HANDLE_MASK ((ULONG_PTR)((LONG)0x80000000))

typedef struct _OBJECT_HANDLE_FLAG_INFORMATION {
	BOOLEAN Inherit;
	BOOLEAN ProtectFromClose;
}OBJECT_HANDLE_FLAG_INFORMATION, * POBJECT_HANDLE_FLAG_INFORMATION;

EXTERN_C NTSTATUS NTAPI ObSetHandleAttributes(HANDLE Handle, POBJECT_HANDLE_FLAG_INFORMATION HandleFlags, KPROCESSOR_MODE PreviousMode);

extern "C" PVOID ObGetObjectType(IN PVOID Object);

namespace handle {
	PHANDLE_TABLE_ENTRY exp_lookup_handle_table_entry(PHANDLE_TABLE handle_table, EXHANDLE handle) noexcept;
	NTSTATUS grant_access(PEPROCESS process, unsigned int access, HANDLE handle = INVALID_HANDLE_VALUE) noexcept;
	NTSTATUS close_handle(PEPROCESS process, HANDLE handle) noexcept;
	NTSTATUS close_handle_by_id(HANDLE process, HANDLE handle) noexcept;
	void release_implicit_locks(PHANDLE_TABLE handle_table, PHANDLE_TABLE_ENTRY handle_table_entry) noexcept;
}