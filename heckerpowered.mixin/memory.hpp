#pragma once
#include <ntifs.h>
#include <intrin.h>
#include "process.hpp"

namespace memory {
	bool should_attach(void* process_id) noexcept;

	NTSTATUS write_virtual_memory(void*& process_id, void*& base_address, const unsigned __int64& buffer_size, void*& buffer) noexcept;
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
	void enable_write_protect(KIRQL irql) noexcept;
	KIRQL disable_write_protect() noexcept;

	void* allocate_contiguous(std::size_t size, bool zero = true) noexcept;
	void free_contiguous(void* address) noexcept;

	template<POOL_TYPE type = POOL_TYPE::NonPagedPoolExecute> void* allocate(std::size_t size, bool zero = true) noexcept
	{
		void* address = ExAllocatePoolWithTag(type, size, 'TRC_');
		if (address == nullptr) return nullptr;
		if (zero) RtlZeroMemory(address, size);

		return address;
	}

	template<unsigned char..._Code>
	inline void execute() noexcept {
		auto function{ allocate(sizeof...(_Code)) };
		std::initializer_list<unsigned char> list{ _Code... };
		memcpy(function, list.begin(), list.size());

		reinterpret_cast<void(__fastcall*)()>(function)();
		free(function);
	}
}