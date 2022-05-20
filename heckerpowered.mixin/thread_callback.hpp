#pragma once

namespace callback::thread
{
	NTSTATUS register_callbacks(PCREATE_THREAD_NOTIFY_ROUTINE routine) noexcept;
	NTSTATUS unregister_callbacks() noexcept;
}