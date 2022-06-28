#pragma once

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

		template<typename T>
		inline const T& response(const T& value) const noexcept {
			*reinterpret_cast<T*>(_buffer) = value;
			return value;
		}

		inline void response(size_t size, void* pointer) const noexcept {
			memcpy(_buffer, pointer, size);
		}

		template<typename T>
		inline std::remove_pointer_t<T>*& response() const noexcept { return *reinterpret_cast<std::remove_pointer_t<T>**>(_buffer); }

		inline T* operator->() const noexcept { return _value; }
		inline T& operator*() const noexcept { return *_value; }

		inline T& value() const noexcept { return *_value; }
	private:
		T* _value;
		void* _buffer;
	};

	template<>
	class request<void> final {
	public:
		inline request(void* buffer) noexcept : _buffer(buffer) {}

		template<typename T>
		inline const T& response(const T& value) const noexcept
		{
			*reinterpret_cast<T*>(_buffer) = value;
			return value;
		}

		inline void response(size_t size, void* pointer) const noexcept
		{
			memcpy(_buffer, pointer, size);
		}

		template<typename T>
		inline std::remove_pointer_t<T>*& response() const noexcept { return reinterpret_cast<std::remove_pointer_t<T>*>(_buffer); }
	private:
		void* _buffer;
	};

	template<typename T>
	void register_request_handler(unsigned int code, std::function<NTSTATUS(request<T>)> handler) {
		auto request_handler = [=](unsigned int length, void* input_buffer, void* out_buffer) {
			if (length != sizeof(T)) { return STATUS_INVALID_BUFFER_SIZE; }

			return handler(request<T>(reinterpret_cast<T*>(input_buffer), out_buffer));
		};

		request_handlers->emplace(code, request_handler);
	}

	NTSTATUS handle_request(unsigned int code, unsigned int length, void* input_buffer, void* out_buffer) noexcept;

	NTSTATUS initialize_requests() noexcept;

	namespace requests {

		namespace legacy
		{
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

			struct memory_request
			{
				void* process_id;
				void* base_address;
				unsigned __int64 size;
				bool disable_interrupt;

				union type_t
				{
					union access_t
					{
						void* buffer;
						int value;
					}access;

					union free_t
					{
						struct allocation_t
						{
							unsigned int allocation_type;
							unsigned int protect;
						}allocation;

						unsigned int free_type;
					}free;

					struct secure_t
					{
						unsigned int probe_mode;
						unsigned int flags;
					}secure;
				}type;

				memory_operation operation;
			};
		}

		enum class memory_operation
		{
			read,
			write
		};

		struct memory_request {
			void* process_id;
			void* base_address;
			void* user_buffer;
			std::size_t size;
			bool is_physical;
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