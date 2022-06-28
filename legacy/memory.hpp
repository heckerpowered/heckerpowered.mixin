#pragma once

namespace memory
{
	NTSTATUS read_process_memory(HANDLE process_id, void* address, bool is_physical, void* user_buffer, std::size_t size, std::size_t& return_size) noexcept;
	NTSTATUS write_process_memory(HANDLE process_id, void* address, bool is_physical, void* user_buffer, std::size_t size, std::size_t& return_size) noexcept;
	std::uint64_t attach(HANDLE process_id) noexcept;
	PHYSICAL_ADDRESS virtual_address_to_physical_address_by_process_id(void* virtual_address, HANDLE process_id) noexcept;

	inline void free(void* address) noexcept { ExFreePoolWithTag(address, crt_pool_tag); }

	#pragma warning(disable: 28167)
	inline void enable_interrupt(KIRQL irql) noexcept
	{
		auto cr0 = __readcr0();
		cr0 |= 0x10000;
		_enable();
		__writecr0(cr0);
		KeLowerIrql(irql);
		KeLeaveGuardedRegion();
	}

	inline KIRQL disable_interrupt(KIRQL level_to_raise = HIGH_LEVEL) noexcept
	{
		KeEnterGuardedRegion();
		const auto irql = KfRaiseIrql(level_to_raise);
		auto cr0 = __readcr0();
		cr0 &= ~(1 << 16);
		__writecr0(cr0);
		_disable();
		return irql;
	}

	template<POOL_FLAGS flags = POOL_FLAG_NON_PAGED_EXECUTE> void* allocate(std::size_t size, bool zero = true) noexcept
	{
		void* address = ExAllocatePool2(flags, size, 'TRC_');
		if (address == nullptr) return nullptr;
		if (zero) RtlZeroMemory(address, size);

		return address;
	}

	template<typename T>
	[[nodiscard]] __declspec(allocator) constexpr T* allocate() noexcept
	{
		return static_cast<T*>(allocate<POOL_FLAG_NON_PAGED>(sizeof(T)));
	}

	template<unsigned char..._Code>
	inline void execute() noexcept
	{
		auto function{ reinterpret_cast<char*>(allocate(sizeof...(_Code))) };
		std::initializer_list<unsigned char> list{ _Code... };
		memcpy(function, list.begin(), list.size()); // std::copy(list.begin(), list.end(), function);

		reinterpret_cast<void(__fastcall*)()>(function)();
		free(function);
	}

	inline std::uint64_t current_cr3() noexcept
	{
		return reinterpret_cast<NT_KPROCESS*>(IoGetCurrentProcess())->DirectoryTableBase;
	}
}