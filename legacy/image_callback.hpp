#pragma once

namespace callback::image {
	NTSTATUS register_callbacks(PLOAD_IMAGE_NOTIFY_ROUTINE routine) noexcept;
	NTSTATUS unregister_callbacks() noexcept;
}