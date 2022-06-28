#pragma once
#include <ntifs.h>
#include "image_callback.hpp"
#include "main.hpp"

namespace cheat {
	namespace eac {
		extern void* eac_base;
		extern size_t eac_base_size;

		NTSTATUS initialize() noexcept;
	}
}