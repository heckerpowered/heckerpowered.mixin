#pragma once
#include <ntifs.h>
#include <string>
#include <vector>
#include <functional>

namespace callback::thread
{
	NTSTATUS register_callbacks(PCREATE_THREAD_NOTIFY_ROUTINE routine) noexcept;
	NTSTATUS unregister_callbacks() noexcept;
}