#pragma once

namespace callback::process {

	struct process_info {
		HANDLE parent_process_id;
		HANDLE process_id;
		struct creating {
			HANDLE process_id;
			HANDLE thread_id;
		} creating;
	};

	NTSTATUS register_callbacks() noexcept;
	NTSTATUS unregister_callbacks() noexcept;
	NTSTATUS wait_for_create() noexcept;
}