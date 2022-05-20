#include "pch.hpp"

namespace proc {
	void* get_kernel_procedure(const wchar_t* system_routine_name) noexcept {
		UNICODE_STRING name;
		RtlInitUnicodeString(&name, system_routine_name);
		return MmGetSystemRoutineAddress(&name);
	}
}