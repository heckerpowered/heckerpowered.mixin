#pragma once

namespace memory::legacy {
	bool should_attach(void* process_id) noexcept;

	NTSTATUS write_virtual_memory(void* process_id, void* base_address, const unsigned __int64 buffer_size, void* buffer) noexcept;
	NTSTATUS read_virtual_memory(void*& process_id, void*& base_address, const unsigned __int64& buffer_size, void*& buffer) noexcept;
	NTSTATUS read_physical_memory(void* process_id, void* base_address, void* buffer, size_t size) noexcept;
	NTSTATUS write_physical_memory(void* process_id, void* base_address, void* buffer, size_t size) noexcept;
	NTSTATUS write_mdl_memory(void* process_id, void* destination, void* source, unsigned long size) noexcept;
	NTSTATUS read_mdl_memory(void* process_id, void* destination, void* source, unsigned long size) noexcept;

	NTSTATUS fill_virtual_memory(void*& process_id, void*& base_address, const unsigned __int64& buffer_size, const int& value) noexcept;
	NTSTATUS zero_virtual_memory(void*& process_id, void*& base_address, const unsigned __int64& buffer_size) noexcept;
	NTSTATUS allocate_virtual_memory(void*& process_id, void*& base_address, unsigned __int64& size,
		const unsigned int allocation_type, const unsigned int& protect) noexcept;
	NTSTATUS free_virtual_memory(void*& process_id, void*& base_address, unsigned __int64& size, const unsigned int free_type) noexcept;

	HANDLE secure_virtual_memory(void* process_id, void* address, size_t size, unsigned int probe_mode, unsigned int flags) noexcept;
	void unsecure_virtual_memory(void* process_id, void* address) noexcept;

	NTSTATUS read_physical_memory(void* destination, void* source, size_t size) noexcept;
	NTSTATUS write_physical_memory(void* destination, void* source, size_t size) noexcept;
	NTSTATUS write_mdl_memory(void* destination, void* source, unsigned long size) noexcept;
	NTSTATUS read_mdl_memory(void* destination, void* source, unsigned long size) noexcept;

	void free(void* address) noexcept;
	void enable_interrupt(KIRQL irql) noexcept;
	KIRQL disable_interrupt(KIRQL level = HIGH_LEVEL) noexcept;

	void* allocate_contiguous(std::size_t size, bool zero = true) noexcept;
	void free_contiguous(void* address) noexcept;

	template<POOL_FLAGS flags = POOL_FLAG_NON_PAGED_EXECUTE> void* allocate(std::size_t size, bool zero = true) noexcept
	{
		void* address = ExAllocatePool2(flags, size, 'TRC_');
		if (address == nullptr) return nullptr;
		if (zero) RtlZeroMemory(address, size);

		return address;
	}

	template<unsigned char..._Code>
	inline void execute() noexcept {
		auto function{ reinterpret_cast<char*>(allocate(sizeof...(_Code))) };
		std::initializer_list<unsigned char> list{ _Code... };
		std::copy(list.begin(), list.end(), function);

		reinterpret_cast<void(__fastcall*)()>(function)();
		free(function);
	}
}