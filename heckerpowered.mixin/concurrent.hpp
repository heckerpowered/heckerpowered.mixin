#pragma once

using namespace std::chrono_literals;

namespace concurrent
{
	class thread
	{
	public:
		using native_handle_type = HANDLE;
	private:
		native_handle_type _native_handle;
		static inline std::unordered_set<HANDLE>* launched_threads;

		inline void destroy(const concurrent::thread& thread) noexcept { launched_threads->erase(thread.native_handle()); }

		template <typename tuple_t, size_t... indices>
		static void __stdcall invoke(void* argument) noexcept
		{
			HANDLE handle{};
			if (NT_SUCCESS(ObOpenObjectByPointer(PsGetCurrentThread(), OBJ_KERNEL_HANDLE, nullptr, THREAD_ALERT, *PsThreadType, MODE::KernelMode,
				&handle))) { launched_threads->emplace(handle); }
			const std::unique_ptr<tuple_t> function(static_cast<tuple_t*>(argument));
			auto& tuple{ *function };
			std::invoke(std::move(std::get<indices>(tuple))...);
			if (handle) { launched_threads->erase(handle); }
			ZwClose(handle);
			PsTerminateSystemThread(STATUS_SUCCESS);
		}

		template <typename tuple_t, size_t... indices>
		[[nodiscard]] static constexpr auto get_invoke(std::index_sequence<indices...>) noexcept
		{
			return &invoke<tuple_t, indices...>;
		}

		template <typename function, typename... args>
		void start(function&& _Fx, args&&... _Ax)
		{
			using tuple = std::tuple<std::decay_t<function>, std::decay_t<args>...>;
			auto deacy_copied{ std::make_unique<tuple>(std::forward<function>(_Fx), std::forward<args>(_Ax)...) };
			constexpr auto invoker{ get_invoke<tuple>(std::make_index_sequence<sizeof...(args) + 1>{}) };

			OBJECT_ATTRIBUTES attribute{};
			InitializeObjectAttributes(&attribute, nullptr, OBJ_KERNEL_HANDLE, nullptr, nullptr);
			PsCreateSystemThread(&_native_handle, THREAD_ALL_ACCESS, &attribute, nullptr, nullptr, invoker, deacy_copied.get());
		}
	public:
		static inline void initialize() { launched_threads = new std::unordered_set<HANDLE>(); }
		inline static void join_all() noexcept { for (auto&& thread : *launched_threads) { ZwWaitForSingleObject(thread, false, nullptr); } }

		template <class function, class... args, std::enable_if_t<!std::is_same_v<std::_Remove_cvref_t<function>, thread>, int> = 0>
		[[nodiscard]] inline explicit thread(function&& _Fx, args&&... _Ax) { start(std::forward<function>(_Fx), std::forward<args>(_Ax)...); }

		[[nodiscard]] inline bool joinable() { return  _native_handle; }

		void join()
		{
			if (!joinable()) { return; }
			ZwWaitForSingleObject(_native_handle, false, nullptr);
			ZwClose(_native_handle);
		}

		void detach()
		{
			if (!joinable()) { return; }
		}

		thread(thread&& _Other) noexcept : _native_handle(std::exchange(_Other._native_handle, {})) {}

		thread& operator=(thread&& _Other) noexcept
		{
			if (joinable()) { _native_handle = std::exchange(_Other._native_handle, {}); }

			return *this;
		}

		thread(const thread&) = delete;
		thread& operator=(const thread&) = delete;
		inline void swap(thread& _Other) noexcept { std::swap(_native_handle, _Other._native_handle); }
		inline native_handle_type native_handle() const noexcept { return _native_handle; }
	};

	inline NTSTATUS exit_thread() { return PsTerminateSystemThread(STATUS_SUCCESS); }

	template <class rep, class period>
	NTSTATUS sleep_for(const std::chrono::duration<rep, period>& duration)
	{
		auto nanoseconds{ std::chrono::duration_cast<std::chrono::nanoseconds>(duration) };
		LARGE_INTEGER kernel_duration{};
		kernel_duration.QuadPart = -nanoseconds.count() / 100;
		return KeDelayExecutionThread(MODE::KernelMode, false, &kernel_duration);
	}

	struct task
	{
		struct promise_type
		{
			auto get_return_object() { return task{}; }
			auto initial_suspend() { return std::suspend_never{}; }
			auto final_suspend() noexcept { return std::suspend_never{}; }
			void unhandled_exception() {}
			void return_void() {}
		};
	};

	template<typename T>
	__forceinline T interlocked_exchange(volatile T* target, const T value) noexcept
	{
		static_assert(sizeof T == sizeof(char) || sizeof T == sizeof(short) || sizeof T == sizeof(int) || sizeof T == sizeof(__int64),
			"Unsupported size.");

		if constexpr (sizeof T == 1) { return _InterlockedExchange8(reinterpret_cast<volatile char*>(target), static_cast<char>(value)); }
		else if constexpr (sizeof T == 2) { return _InterlockedExchange16(reinterpret_cast<volatile short*>(target), static_cast<short*>(value)); }
		else if constexpr (sizeof T == 4) { return _InterlockedExchange(reinterpret_cast<volatile long*>(target), static_cast<long>(value)); }
		else if constexpr (sizeof T == 8) { return _InterlockedExchange64(reinterpret_cast<volatile __int64*>(target), static_cast<long>(value)); }
	}

	template<typename T>
	inline T interlocked_or(volatile T* target, const T value) noexcept
	{
		static_assert(sizeof T == sizeof(char) || sizeof T == sizeof(short) || sizeof T == sizeof(int) || sizeof T == sizeof(__int64),
			"Unsupported size.");

		if constexpr (sizeof T == 1) { return _InterlockedOr8(reinterpret_cast<volatile char*>(target), static_cast<char>(value)); }
		else if constexpr (sizeof T == 2) { return _InterlockedOr16(reinterpret_cast<volatile short*>(target), static_cast<short*>(value)); }
		else if constexpr (sizeof T == 4) { return _InterlockedOr(reinterpret_cast<volatile long*>(target), static_cast<long>(value)); }
		else if constexpr (sizeof T == 8) { return _InterlockedOr64(reinterpret_cast<volatile __int64*>(target), static_cast<long>(value)); }
	}

	template<typename T>
	inline T interlocked_xor(volatile T* target, const T value) noexcept
	{
		static_assert(sizeof T == sizeof(char) || sizeof T == sizeof(short) || sizeof T == sizeof(int) || sizeof T == sizeof(__int64),
			"Unsupported size.");

		if constexpr (sizeof T == 1) { return _InterlockedXor8(reinterpret_cast<volatile char*>(target), static_cast<char>(value)); }
		else if constexpr (sizeof T == 2) { return _InterlockedXor16(reinterpret_cast<volatile short*>(target), static_cast<short*>(value)); }
		else if constexpr (sizeof T == 4) { return _InterlockedXor(reinterpret_cast<volatile long*>(target), static_cast<long>(value)); }
		else if constexpr (sizeof T == 8) { return _InterlockedXor64(reinterpret_cast<volatile __int64*>(target), static_cast<long>(value)); }
	}

	template<typename T>
	inline T interlocked_increment(volatile T* target) noexcept
	{
		static_assert(sizeof T == sizeof(short) || sizeof T == sizeof(int) || sizeof T == sizeof(__int64),
			"Unsupported size.");

		if constexpr (sizeof T == 2) { return _InterlockedIncrement16(reinterpret_cast<volatile short*>(target)); }
		else if constexpr (sizeof T == 4) { return _InterlockedIncrement(reinterpret_cast<volatile long*>(target)); }
		else if constexpr (sizeof T == 8) { return _InterlockedIncrement64(reinterpret_cast<volatile __int64*>(target)); }
	}

	template<typename T>
	inline T interlocked_decrement(volatile T* target) noexcept
	{
		static_assert(sizeof T == sizeof(short) || sizeof T == sizeof(int) || sizeof T == sizeof(__int64),
			"Unsupported size.");

		if constexpr (sizeof T == 2) { return _InterlockedDecrement16(reinterpret_cast<volatile short*>(target)); }
		else if constexpr (sizeof T == 4) { return _InterlockedDecrement(reinterpret_cast<volatile long*>(target)); }
		else if constexpr (sizeof T == 8) { return _InterlockedDecrement64(reinterpret_cast<volatile __int64*>(target)); }
	}

	template<typename T>
	inline T interlocked_add(volatile T* target, T value) noexcept
	{
		static_assert(sizeof T == sizeof(short) || sizeof T == sizeof(int) || sizeof T == sizeof(__int64),
			"Unsupported size.");

		if constexpr (sizeof T == 1) { return _InterlockedExchangeAdd8(reinterpret_cast<volatile char*>(target), static_cast<char>(value)); }
		else if constexpr (sizeof T == 2) { return _InterlockedExchangeAdd16(reinterpret_cast<volatile char*>(target), static_cast<char>(value)); }
		else if constexpr (sizeof T == 4) { return _InterlockedExchangeAdd(reinterpret_cast<volatile char*>(target), static_cast<char>(value)); }
		else if constexpr (sizeof T == 8) { return _InterlockedExchangeAdd64(reinterpret_cast<volatile char*>(target), static_cast<char>(value)); }
	}

	inline void interlocked_copy(void* destination, const void* source, std::size_t length) noexcept
	{
		if (destination == nullptr || source == nullptr) { return; }

		auto destination_pointer{ reinterpret_cast<char*>(destination) };
		auto source_pointer{ reinterpret_cast<const char*>(source) };
		if (destination_pointer <= source_pointer || destination_pointer >= source_pointer + length)
		{
			while (length--)
			{
				interlocked_exchange(destination_pointer, *source_pointer);
				destination_pointer++;
				source_pointer++;
			}
		}
		else
		{
			source_pointer += length - 1;
			destination_pointer += length - 1;
			while (length--)
			{
				interlocked_exchange(destination_pointer, *source_pointer);
				destination_pointer--;
				source_pointer--;
			}
		}
	}
}