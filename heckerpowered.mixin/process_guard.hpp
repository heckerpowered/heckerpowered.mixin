#pragma once
#include <ntifs.h>
#include "kernel_stl.hpp"
#include <unordered_set>
#include "infinity_hook.hpp"
#include "procedure.hpp"
#include "process.hpp"
#include "inline_hook.hpp"
#include "ssdt.hpp"
#include "image_callback.hpp"

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

namespace guard {
	enum class guard_level
	{
		disabled,
		basic,
		strict,
		highest,
	};

	void raise_guard_level(HANDLE process_id, guard_level level) noexcept;
	void disable_guard(void* process_id) noexcept;
	bool guarded(void* process_id) noexcept;
	bool require(HANDLE process_id, guard_level level) noexcept;
	void initialize();
}