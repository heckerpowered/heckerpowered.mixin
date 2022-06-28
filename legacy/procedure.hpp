#pragma once

namespace proc {
	void* get_kernel_procedure(const wchar_t* system_routine_name) noexcept;
}

inline namespace proc_literals {
	#pragma warning(disable: 4455)
	[[nodiscard]] inline unsigned char* operator"" e(const wchar_t* name, size_t) {
		return static_cast<unsigned char*>(proc::get_kernel_procedure(name));
	}
	#pragma warning(default: 4455)
}