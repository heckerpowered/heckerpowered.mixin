#pragma once

#include <ntifs.h>
#include "kernel_stl.hpp"
#include <functional>
#include <unordered_map>
#include "process.hpp"
#include "process_guard.hpp"
#include "memory.hpp"
#include "util.hpp"
#include "thread.hpp"
#include "process_callback.hpp"
#include "handle.hpp"
#include "compatibility.hpp"
#include "system.hpp"

namespace com {
	using request_handler = std::function<NTSTATUS(unsigned int, void*, void*)>;

	extern std::unordered_map<unsigned int, request_handler>* request_handlers;

	constexpr inline unsigned short extract_method(unsigned long io_ctl) {
		return io_ctl & 0B11;
	}

	template<typename T>
	class request final {
	public:
		inline request(T* value, void* buffer) noexcept : _value(value), _buffer(buffer) {}

		template<typename data_type>
		inline void response(data_type value) const noexcept {
			*reinterpret_cast<data_type*>(_buffer) = value;
		}

		inline void response(size_t size, void* pointer) const noexcept {
			memcpy(_buffer, pointer, size);
		}

		inline T& value() const noexcept { return *_value; }
	private:
		T* _value;
		void* _buffer;
	};

	template<>
	class request<void> final {
	public:
		inline request(void* buffer) noexcept : _buffer(buffer) {}

		template<typename data_type>
		inline void response(data_type value) const noexcept {
			*reinterpret_cast<data_type*>(_buffer) = value;
		}
	private:
		void* _buffer;
	};

	template<typename T>
	void register_request_handler(unsigned int code, std::function<NTSTATUS(request<T>)> handler) {
		auto request_handler = [=](unsigned int length, void* input_buffer, void* out_buffer) {
			if (length != sizeof(T)) {
				return STATUS_INVALID_BUFFER_SIZE;
			}

			return handler(request<T>(reinterpret_cast<T*>(input_buffer), out_buffer));
		};

		request_handlers->emplace(code, request_handler);
	}

	NTSTATUS handle_request(unsigned int code, unsigned int length, void* input_buffer, void* out_buffer) noexcept;

	NTSTATUS initialize_requests() noexcept;

	namespace requests {
		enum class memory_operation
		{
			read_virtual,
			write_virtual,
			fill_virtual,
			zero_virtual,
			allocate_virtual,
			free_virtual,
			secure_virtual,
			unsecure_virtual,
			write_physical,
			read_physical,
			write_mdl,
			read_mdl
		};

		struct memory_request {
			void* process_id;
			void* base_address;
			unsigned __int64 size;
			bool disable_protection;
			#pragma warning(disable: 4201)
			union {
				union {
					void* buffer;
					int value;
				};
				union {
					struct {
						unsigned int allocation_type;
						unsigned int protect;
					};
					unsigned int free_type;
				};
				struct {
					unsigned int probe_mode;
					unsigned int flags;
				};
			};
			#pragma warning(default: 4201)
			memory_operation operation;
		};

		struct buffer {
			void* pointer;
			size_t size;
		};

		struct accessible {
			void* process_id;
			bool accessible;
		};

		struct elevate_handle_access {
			HANDLE process_id;
			HANDLE handle;
			unsigned int access;
		};

		struct close_handle {
			HANDLE process_id;
			HANDLE handle;
		};

		struct process_guard
		{
			guard::guard_level level;
			HANDLE process_id;
		};
	}
}