#pragma once

#define INFINITY_HOOK_SUPPORT

#include "hook.hpp"
#include "procedure.hpp"
#include "kernel_stl.hpp"
#include <unordered_map>
#include "ssdt.hpp"

namespace hook {
	NTSTATUS initialize();
	void hook_export(const wchar_t* function_name, void* address) noexcept;
	void hook_ssdt(const char* ssdt_name, void* address) noexcept;
	inline void hook_function(void* function, void* address) noexcept;
}