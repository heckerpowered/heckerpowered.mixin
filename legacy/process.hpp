#pragma once

namespace process
{
	enum class protect_flag
	{
		disable,
		enable,
		keep
	};

	NTSTATUS get_process_by_id(void* process_id, PEPROCESS& process) noexcept;
	NTSTATUS open_process_by_id(void* process_id, void*& process, unsigned int access_mask = PROCESS_ALL_ACCESS) noexcept;
	NTSTATUS open_process(PEPROCESS process, void*& handle, unsigned int access_mask = PROCESS_ALL_ACCESS,
		unsigned int attributes = OBJ_KERNEL_HANDLE, KPROCESSOR_MODE processor_mode = MODE::KernelMode) noexcept;
	NTSTATUS terminate_process(PEPROCESS process, NTSTATUS exit_status = STATUS_SUCCESS) noexcept;
	NTSTATUS terminate_process_by_id(void* process, NTSTATUS exit_status = STATUS_SUCCESS) noexcept;
	NTSTATUS suspend_process(PEPROCESS process) noexcept;
	NTSTATUS suspend_process_by_id(void* process) noexcept;
	NTSTATUS resume_process(PEPROCESS process) noexcept;
	NTSTATUS resume_process_by_id(void* process_id) noexcept;
	NTSTATUS query_information_process(void* process, PROCESSINFOCLASS process_information_class, void* process_information,
		unsigned int process_information_length, unsigned int& return_length) noexcept;
	NTSTATUS set_information_process(void* process, PROCESSINFOCLASS process_information_class, void* process_information,
		unsigned int process_information_length) noexcept;
	bool is_32bit(void* process = ZwCurrentProcess()) noexcept;
	bool is_32bit_by_id(void* process_id = PsGetCurrentProcessId()) noexcept;
	bool is_64bit(PEPROCESS process) noexcept;
	bool is_64bit_by_id(void* process_id = PsGetCurrentProcessId()) noexcept;
	bool is_terminating(PEPROCESS process) noexcept;
	NTSTATUS lookup_process_thread(PEPROCESS process, std::vector<PETHREAD>& threads);
	bool satisfy_apc_requirements(PETHREAD thread, bool wow64) noexcept;
	NTSTATUS set_protect_flag(PEPROCESS process, protect_flag protection, protect_flag dynamic_code = protect_flag::keep,
		protect_flag signature = protect_flag::keep) noexcept;
	NTSTATUS set_protect_flag_by_id(HANDLE process_id, protect_flag protection, protect_flag dynamic_code = protect_flag::keep,
		protect_flag signature = protect_flag::keep) noexcept;

	inline NTSTATUS handle_to_process(HANDLE handle, PEPROCESS& process) noexcept
	{
		return ObReferenceObjectByHandle(handle, PROCESS_ALL_ACCESS, *PsProcessType, MODE::KernelMode, reinterpret_cast<void**>(process), nullptr);
	}
}