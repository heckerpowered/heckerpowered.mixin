#pragma once
#include <ntifs.h>
#include "kernel_stl.hpp"
#include <unordered_map>
#include <functional>
#include "memory.hpp"
#include "lde.hpp"

namespace hook::inline_hook {
	void initialize() noexcept;
	void uninstall_hooks() noexcept;
	void hook(void* victim, void* target) noexcept;
	void* get_unhooked(void* victim) noexcept;
}