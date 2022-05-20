#pragma once

namespace thread
{
	using user_thread_routine = NTSTATUS(__stdcall*)(void*);
	NTSTATUS open_thread_by_id(void* thread_id, void*& handle, unsigned int access_mask = THREAD_ALL_ACCESS) noexcept;
	NTSTATUS open_thread(PETHREAD thread, void*& handle, unsigned int access_mask = THREAD_ALL_ACCESS,
		unsigned int attributes = OBJ_KERNEL_HANDLE, KPROCESSOR_MODE mode = MODE::KernelMode) noexcept;
	NTSTATUS create_user_thread_by_handle(void* process, user_thread_routine start_address, void* argument, bool create_suspended,
		void*& thread, CLIENT_ID& client_id) noexcept;
	NTSTATUS create_system_thread_by_handle(void* process, PKSTART_ROUTINE start_address, void* argument, void*& thread, CLIENT_ID& client_id) noexcept;
	NTSTATUS create_system_thread(PKSTART_ROUTINE start_address, void* argument, void*& thread) noexcept;
	NTSTATUS create_system_thread_by_id(void* process_id, PKSTART_ROUTINE start_address, void* argument, void*& thread, CLIENT_ID& client_id) noexcept;
	PEPROCESS thread_to_process(PETHREAD thread) noexcept;
	NTSTATUS queue_user_apc(PETHREAD thread, void* user_function, void* arg1, void* arg2, void* arg3, bool force) noexcept;
}