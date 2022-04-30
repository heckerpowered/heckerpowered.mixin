#pragma once
#include <ntifs.h>
#include "process_protection.hpp"
#include "process.hpp"
#include <set>
#include <string>
#include <deque>

namespace callback::process {

	struct process_info {
		HANDLE parent_process_id;
		HANDLE process_id;
		struct creating {
			HANDLE process_id;
			HANDLE thread_id;
		} creating;
	};

	extern std::deque<process_info> created_processes;

	NTSTATUS register_callbacks() noexcept;
	NTSTATUS unregister_callbacks() noexcept;
	NTSTATUS wait_for_create() noexcept;
}