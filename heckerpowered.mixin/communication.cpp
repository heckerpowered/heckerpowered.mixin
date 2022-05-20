#include "pch.hpp"

namespace com {
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

	NTSTATUS handle_request(unsigned int code, unsigned int length, void* input_buffer, void* out_buffer) noexcept {
		__try {
			if (input_buffer == nullptr || out_buffer == nullptr) return STATUS_NOT_SUPPORTED;

			auto result = request_handlers->find(code);
			if (result == request_handlers->end()) return STATUS_INVALID_PARAMETER;

			return result->second(length, input_buffer, out_buffer);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			return _exception_code();
		}
	}

	NTSTATUS initialize_requests() noexcept {
		constexpr auto function_offset = 2049;
		constexpr auto function_memory = CTL_CODE(FILE_DEVICE_UNKNOWN, function_offset, METHOD_BUFFERED, FILE_ANY_ACCESS);
		constexpr auto function_protect = CTL_CODE(FILE_DEVICE_UNKNOWN, function_offset + 1, METHOD_BUFFERED, FILE_ANY_ACCESS);
		constexpr auto function_terminate = CTL_CODE(FILE_DEVICE_UNKNOWN, function_offset + 2, METHOD_BUFFERED, FILE_ANY_ACCESS);
		constexpr auto function_open_process = CTL_CODE(FILE_DEVICE_UNKNOWN, function_offset + 3, METHOD_BUFFERED, FILE_ANY_ACCESS);
		constexpr auto function_escape_debugger = CTL_CODE(FILE_DEVICE_UNKNOWN, function_offset + 4, METHOD_BUFFERED, FILE_ANY_ACCESS);
		constexpr auto function_set_system_thread = CTL_CODE(FILE_DEVICE_UNKNOWN, function_offset + 5, METHOD_BUFFERED, FILE_ANY_ACCESS);
		constexpr auto function_elevate_handle_access = CTL_CODE(FILE_DEVICE_UNKNOWN, function_offset + 6, METHOD_BUFFERED, FILE_ANY_ACCESS);
		constexpr auto function_exit_windows = CTL_CODE(FILE_DEVICE_UNKNOWN, function_offset + 7, METHOD_BUFFERED, FILE_ANY_ACCESS);
		
		__try {
			request_handlers = new std::unordered_map<unsigned int, request_handler>();
			
			register_request_handler<requests::memory_request>(function_memory, [](request<requests::memory_request> request) {
				decltype(auto) memory_request{ request.value() };
				auto process_id{ memory_request.process_id };
				auto base_address{ memory_request.base_address };
				auto buffer{ memory_request.buffer };
				auto size{ memory_request.size };
				auto disable_protection{ memory_request.disable_protection };

				KIRQL irql{};
				if (disable_protection) {
					irql = memory::disable_interrupt();
				}

				NTSTATUS status{};
					switch (memory_request.operation) {
						case requests::memory_operation::read_virtual:
							status = memory::read_virtual_memory(process_id, base_address, size, buffer);
							break;
						case requests::memory_operation::write_virtual:
							status = memory::write_virtual_memory(process_id, base_address, size, buffer);
							break;
						case requests::memory_operation::fill_virtual:
							status = memory::fill_virtual_memory(process_id, base_address, size, memory_request.value);
							break;
						case requests::memory_operation::zero_virtual:
							status = memory::zero_virtual_memory(process_id, base_address, size);
							break;
						case requests::memory_operation::allocate_virtual:
							status = memory::allocate_virtual_memory(process_id, base_address, size, memory_request.allocation_type,
								memory_request.protect);
							request.response(base_address);
							break;
						case requests::memory_operation::free_virtual:
							status =  memory::free_virtual_memory(process_id, base_address, size, memory_request.free_type);
						case requests::memory_operation::secure_virtual:
						{
							auto result = memory::secure_virtual_memory(process_id, base_address, size, memory_request.probe_mode, memory_request.flags);
							if (result == nullptr)
							{
								status = STATUS_UNSUCCESSFUL;
								break;
							}

							request.response<HANDLE>(result);
							status = STATUS_SUCCESS;
							break;
						}
						case requests::memory_operation::unsecure_virtual:
							memory::unsecure_virtual_memory(process_id, base_address);
							status = STATUS_SUCCESS;
						case requests::memory_operation::read_physical:
							status = memory::read_physical_memory(process_id, base_address, buffer, size);
							break;
						case requests::memory_operation::write_physical:
							status = memory::write_physical_memory(process_id, base_address, buffer, size);
							break;
						default:
							status = STATUS_INVALID_PARAMETER;
							break;
					}

					if (disable_protection) memory::enable_interrupt(irql);
					return status;
			});
			
			register_request_handler<requests::process_guard>(function_protect, [](request<requests::process_guard> request) {
				guard::raise_guard_level(request.value().process_id, request.value().level);
				return STATUS_SUCCESS;
			});

			register_request_handler<void*>(function_terminate, [](request<void*> request) {
				return process::terminate_process_by_id(request.value());
			});

			register_request_handler<void*>(function_open_process, [](request<void*> request) {

				// The handle opened with the "ObOpenObjectByPointer" method can
				// be correctly passed to the user side. For the kernel side, this handle
				// has the expected access rights, but for the user side, this handle may
				// not have the expected access rights. For example, if a process
				// handle is opened on the kernel side using
				// "ObOpenObjectByPointer", but the target process uses the
				// "POB_PRE_OPERATION_CALLBACK callback" to restrict access, then
				// access is not restricted on the kernel side, but access will be
				// restricted if the handle is passed to the user side. Although the
				// parameter "HandleAttributes" is 0.
				//
				// The process handle opened by "ZwOpenProcess" will always have
				// the expected access even if it is passed to the user side.
				#ifdef OPEN_PROCESS_BY_ZWAPI
				HANDLE handle;
				OBJECT_ATTRIBUTES attribute{};
				InitializeObjectAttributes(&attribute, nullptr, 0, nullptr, nullptr);
				CLIENT_ID id{};
				id.UniqueProcess = request.value();
				auto status = ZwOpenProcess(&handle, PROCESS_ALL_ACCESS, &attribute, &id);
				request.response(handle);
				#else

				auto previous_mode{ util::set_previous_mode(MODE::KernelMode) };
				HANDLE process;
				auto status{ process::open_process_by_id(request.value(), process) };
				if (NT_SUCCESS(status)) { request.response(process); }
				
				util::set_previous_mode(previous_mode);
				#endif
				return status;
			});

			register_request_handler<void*>(function_escape_debugger, [](request<void*> request) {
				PEPROCESS process{};
				auto status = process::get_process_by_id(request.value(), process);
				if (!NT_SUCCESS(status)) return status;

				return compatibility::set_debug_port(process, 0);
			});

			// KeBugCheck
			register_request_handler<HANDLE>(function_set_system_thread, [](request<HANDLE> request) {
				PETHREAD thread;
				auto status = PsLookupThreadByThreadId(request.value(), &thread);
				if (!NT_SUCCESS(status)) return status;
					
				compatibility::set_system_thread(thread, true);

				return STATUS_SUCCESS;
			});

			register_request_handler<requests::elevate_handle_access>(function_elevate_handle_access, [](request<requests::elevate_handle_access> request) {
				auto&& elevate = request.value();
				PEPROCESS process;
				auto status{ PsLookupProcessByProcessId(elevate.process_id, &process) };
				if (!NT_SUCCESS(status)) { return status; }

				return handle::grant_access(process, elevate.access, elevate.handle);
			});

			register_request_handler<void>(function_exit_windows, [](request<void> request [[maybe_unused]]) {
				auto previous_mode{ util::set_previous_mode(MODE::KernelMode) };
				sys::shutdown();
				util::set_previous_mode(previous_mode);
				return STATUS_SUCCESS;
			});
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			return _exception_code();
		}

		return STATUS_SUCCESS;
	}
}