#pragma once
#include <ntifs.h>
#include "kernel_stl.hpp"
#include <unordered_set>
#include "infinity_hook.hpp"
#include "procedure.hpp"
#include "process.hpp"
#include "inline_hook.hpp"
#include "ssdt.hpp"

extern "C" NTSYSAPI NTSTATUS NtOpenThread(
	_Out_ PHANDLE            ThreadHandle,
	_In_  ACCESS_MASK        DesiredAccess,
	_In_  POBJECT_ATTRIBUTES ObjectAttributes,
	_In_  PCLIENT_ID         ClientId
);

extern "C" NTSYSAPI NTSTATUS ZwOpenThread(
	_Out_ PHANDLE            ThreadHandle,
	_In_  ACCESS_MASK        DesiredAccess,
	_In_  POBJECT_ATTRIBUTES ObjectAttributes,
	_In_  PCLIENT_ID         ClientId
);

namespace protect {
	void begin_protect(void* process_id) noexcept;
	void end_protect(void* process_id) noexcept;
	bool is_protected(void* process_id) noexcept;
	void initialize();
}