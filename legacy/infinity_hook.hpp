#pragma once

namespace hook::infinity_hook
{
	NTSTATUS initialize();
	void hook_export(const wchar_t* function_name, void* address) noexcept;
	void hook_ssdt(const char* ssdt_name, void* address) noexcept;
	inline void hook_function(void* function, void* address) noexcept;
}