#pragma once
#ifdef ENABLE_VIRTUALIZATION

#include <ntifs.h>
#include <unordered_map>
#include <optional>
#include "nmd_assembly.hpp"
#include "util.hpp"
#include "virtualization_assembly.hpp"

namespace hook::virtual_hook
{
	struct virtual_hook
	{
		unsigned __int64 real_page;
		unsigned __int64 fake_page;
		unsigned __int64 fake_virtual_page;
		unsigned __int64 original_function;
		unsigned __int64 original_function_code;
		bool free;
	};

	void unhook() noexcept;
	void unhook(unsigned __int64 address) noexcept;
	void* hook(unsigned __int64 address, void* proxy) noexcept;
	std::optional<virtual_hook> get_hook(unsigned __int64 address) noexcept;
	void initialize() noexcept;
}
#endif