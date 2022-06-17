#pragma once

namespace hook::inline_hook {
	void initialize() noexcept;
	void uninstall_hooks() noexcept;
	void hook(void* victim, void* target) noexcept;
	void* get_unhooked(void* victim) noexcept;
	void* hook_internal(void* victim, void* target, void*& original, std::size_t& patch_size);
}