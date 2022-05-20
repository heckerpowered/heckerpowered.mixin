#pragma once

namespace hook::inline_hook {
	void initialize() noexcept;
	void uninstall_hooks() noexcept;
	void hook(void* victim, void* target) noexcept;
	void* get_unhooked(void* victim) noexcept;
}