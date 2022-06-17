#include "pch.hpp"

namespace com
{
	std::unordered_map<unsigned int, request_handler>* request_handlers;

	template<>
	void register_request_handler<void>(unsigned int code, std::function<NTSTATUS(request<void>)> handler)
	{
		auto request_handler = [=](unsigned int length [[maybe_unused]], void* input_buffer [[maybe_unused]], void* out_buffer)
		{
			return handler(request<void>(out_buffer));
		};

		request_handlers->emplace(code, request_handler);
	}

	NTSTATUS handle_request(unsigned int code, unsigned int length, void* input_buffer, void* out_buffer) noexcept
	{
		__try
		{
			if (input_buffer == nullptr || out_buffer == nullptr) return STATUS_NOT_SUPPORTED;

			auto result = request_handlers->find(code);
			if (result == request_handlers->end()) return STATUS_INVALID_PARAMETER;

			return result->second(length, input_buffer, out_buffer);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			return _exception_code();
		}
	}

	NTSTATUS initialize_requests() noexcept
	{
		constexpr auto function_offset = 2049;
		constexpr auto function_memory = CTL_CODE(FILE_DEVICE_UNKNOWN, function_offset, METHOD_BUFFERED, FILE_ANY_ACCESS);
		constexpr auto function_protect = CTL_CODE(FILE_DEVICE_UNKNOWN, function_offset + 1, METHOD_BUFFERED, FILE_ANY_ACCESS);
		constexpr auto function_terminate = CTL_CODE(FILE_DEVICE_UNKNOWN, function_offset + 2, METHOD_BUFFERED, FILE_ANY_ACCESS);
		constexpr auto function_open_process = CTL_CODE(FILE_DEVICE_UNKNOWN, function_offset + 3, METHOD_BUFFERED, FILE_ANY_ACCESS);
		constexpr auto function_escape_debugger = CTL_CODE(FILE_DEVICE_UNKNOWN, function_offset + 4, METHOD_BUFFERED, FILE_ANY_ACCESS);
		constexpr auto function_set_system_thread = CTL_CODE(FILE_DEVICE_UNKNOWN, function_offset + 5, METHOD_BUFFERED, FILE_ANY_ACCESS);
		constexpr auto function_elevate_handle_access = CTL_CODE(FILE_DEVICE_UNKNOWN, function_offset + 6, METHOD_BUFFERED, FILE_ANY_ACCESS);
		constexpr auto function_exit_windows = CTL_CODE(FILE_DEVICE_UNKNOWN, function_offset + 7, METHOD_BUFFERED, FILE_ANY_ACCESS);
		constexpr auto function_memory_legacy = CTL_CODE(FILE_DEVICE_UNKNOWN, function_offset + 8, METHOD_BUFFERED, FILE_ANY_ACCESS);

		__try
		{
			request_handlers = new std::unordered_map<unsigned int, request_handler>();

			register_request_handler<requests::legacy::memory_request>(function_memory_legacy, [](request<requests::legacy::memory_request> request)
			{
				KIRQL irql{};
				if (request->disable_interrupt) { irql = memory::disable_interrupt(APC_LEVEL); }

				NTSTATUS status{};
				switch (request->operation)
				{
					case requests::legacy::memory_operation::read_virtual:
						status = memory::legacy::read_virtual_memory(request->process_id, request->base_address, request->size, request->type.access.buffer);
						break;
					case requests::legacy::memory_operation::write_virtual:
						status = memory::legacy::write_virtual_memory(request->process_id, request->base_address, request->size, request->type.access.buffer);
						break;
					case requests::legacy::memory_operation::fill_virtual:
						status = memory::legacy::fill_virtual_memory(request->process_id, request->base_address, request->size, request->type.access.value);
						break;
					case requests::legacy::memory_operation::zero_virtual:
						status = memory::legacy::zero_virtual_memory(request->process_id, request->base_address, request->size);
						break;
					case requests::legacy::memory_operation::allocate_virtual:
						status = memory::legacy::allocate_virtual_memory(request->process_id, request.response<void*>(), request->size,
							request->type.free.allocation.allocation_type, request->type.free.allocation.protect);
						break;
					case requests::legacy::memory_operation::free_virtual:
						status = memory::legacy::free_virtual_memory(request->process_id, request->base_address, request->size, request->type.free.free_type);
					case requests::legacy::memory_operation::secure_virtual:
					{
						auto result = memory::legacy::secure_virtual_memory(request->process_id, request->base_address, request->size, request->type.secure.probe_mode,
							request->type.secure.flags);
						if (result == nullptr)
						{
							status = STATUS_UNSUCCESSFUL;
							break;
						}

						request.response<HANDLE>(result);
						status = STATUS_SUCCESS;
						break;
					}
					case requests::legacy::memory_operation::unsecure_virtual:
						memory::legacy::unsecure_virtual_memory(request->process_id, request->base_address);
						status = STATUS_SUCCESS;
						break;
					case requests::legacy::memory_operation::read_physical:
						status = memory::legacy::read_physical_memory(request->process_id, request->base_address, request->type.access.buffer, request->size);
						break;
					case requests::legacy::memory_operation::write_physical:
						status = memory::legacy::write_physical_memory(request->process_id, request->base_address, request->type.access.buffer, request->size);
						break;
					default:
						status = STATUS_INVALID_PARAMETER;
						break;
				}

				if (request->disable_interrupt) { memory::enable_interrupt(irql); }
				return status;
			});

			register_request_handler<requests::memory_request>(function_memory, [](request<requests::memory_request> request)
			{
				switch (request->operation)
				{
					case requests::memory_operation::read:
						return memory::read_process_memory(request->process_id, request->base_address, request->is_physical, request->user_buffer, request->size,
							*request.response<std::size_t>());
					case requests::memory_operation::write:
						return STATUS_NOT_IMPLEMENTED	;
					default:
						return STATUS_NOT_SUPPORTED;
				}
			});

			register_request_handler<requests::process_guard>(function_protect, [](request<requests::process_guard> request)
			{
				guard::raise_guard_level(request->process_id, request.value().level);
				return STATUS_SUCCESS;
			});

			register_request_handler<void*>(function_terminate, [](request<void*> request)
			{
				return process::terminate_process_by_id(*request);
			});

			register_request_handler<void*>(function_open_process, [](request<void*> request)
			{
				auto previous_mode{ util::set_previous_mode(MODE::KernelMode) };
				HANDLE process;
				auto status{ process::open_process_by_id(request.value(), process) };
				if (NT_SUCCESS(status)) { request.response(process); }

				util::set_previous_mode(previous_mode);

				return status;
			});

			register_request_handler<void*>(function_escape_debugger, [](request<void*> request)
			{
				PEPROCESS process{};
				auto status = process::get_process_by_id(request.value(), process);
				if (!NT_SUCCESS(status)) return status;

				return compatibility::set_debug_port(process, 0);
			});

			// KeBugCheck
			register_request_handler<HANDLE>(function_set_system_thread, [](request<HANDLE> request)
			{
				PETHREAD thread;
				auto status = PsLookupThreadByThreadId(request.value(), &thread);
				if (!NT_SUCCESS(status)) return status;

				compatibility::set_system_thread(thread, true);

				return STATUS_SUCCESS;
			});

			register_request_handler<requests::elevate_handle_access>(function_elevate_handle_access, [](request<requests::elevate_handle_access> request)
			{
				auto&& elevate = request.value();
				PEPROCESS process;
				auto status{ PsLookupProcessByProcessId(elevate.process_id, &process) };
				if (!NT_SUCCESS(status)) { return status; }

				return handle::grant_access(process, elevate.access, elevate.handle);
			});

			register_request_handler<void>(function_exit_windows, [](request<void> request [[maybe_unused]] )
			{
				auto previous_mode{ util::set_previous_mode(MODE::KernelMode) };
				sys::shutdown();
				util::set_previous_mode(previous_mode);
				return STATUS_SUCCESS;
			});
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			return _exception_code();
		}

		return STATUS_SUCCESS;
	}
}