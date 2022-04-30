#pragma once
#include <ntifs.h>
#include <string>
#include <vector>
#include <functional>

namespace callback::image {
	NTSTATUS register_callbacks(PLOAD_IMAGE_NOTIFY_ROUTINE routine) noexcept;
	NTSTATUS unregister_callbacks() noexcept;
}