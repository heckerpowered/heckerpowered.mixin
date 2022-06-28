#pragma once
#include "extern.hpp"
#include "procedure.hpp"

namespace patch_guard {
	NTSTATUS disable_patchguard(struct _DRIVER_OBJECT* driver_object) noexcept;
}