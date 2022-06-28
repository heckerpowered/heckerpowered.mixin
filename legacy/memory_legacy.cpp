#include "pch.hpp"

namespace memory::legacy
{
	constexpr unsigned long crt_pool_tag = 'TRC_';

	bool should_attach(void* process_id) noexcept
	{
		return PsGetCurrentProcessId() != process_id;
	}

	NTSTATUS write_virtual_memory(void* process_id, void* base_address, const unsigned __int64 buffer_size, void* buffer) noexcept
	{
		PEPROCESS process;
		const auto status = PsLookupProcessByProcessId(process_id, &process);
		if (!NT_SUCCESS(status))
		{
			return status;
		}

		auto kernel_buffer = allocate(buffer_size);
		if (kernel_buffer == nullptr)
		{

			// If ExAllocatePool returns null,
			// we should return the NTSTATUS value STATUS_INSUFFICIENT_RESOURCES
			// or should delay processing to another point in time.
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		memcpy(kernel_buffer, buffer, buffer_size);

		const bool should_attach = legacy::should_attach(process_id);
		KAPC_STATE state;
		if (should_attach) KeStackAttachProcess(process, &state);
		__try
		{
			ProbeForWrite(base_address, buffer_size, sizeof(char));
			memcpy(base_address, kernel_buffer, buffer_size);
			if (should_attach) KeUnstackDetachProcess(&state);
		}
		// Handle any possible exceptions.
		#pragma warning(disable: 6320)
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			#pragma warning(default: 6320)
			if (should_attach) KeUnstackDetachProcess(&state);

			return _exception_code();
		}

		ExFreePool(kernel_buffer);
		return status;
	}

	NTSTATUS read_virtual_memory(void*& process_id, void*& base_address, const unsigned __int64& buffer_size, void*& buffer) noexcept
	{
		PEPROCESS process;
		const auto status = PsLookupProcessByProcessId(process_id, &process);
		if (!NT_SUCCESS(status))
		{
			return status;
		}

		auto kernel_buffer = legacy::allocate(buffer_size);
		if (kernel_buffer == nullptr)
		{

			// If ExAllocatePool returns null,
			// we should return the NTSTATUS value STATUS_INSUFFICIENT_RESOURCES
			// or should delay processing to another point in time.
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		const bool should_attach = legacy::should_attach(process_id);

		KAPC_STATE state;
		if (should_attach) KeStackAttachProcess(process, &state);

		__try
		{
			ProbeForRead(base_address, buffer_size, sizeof(char));
			memcpy(kernel_buffer, base_address, buffer_size);
			if (should_attach) KeUnstackDetachProcess(&state);
		}
		// Handle any possible exceptions.
		#pragma warning(disable: 6320)
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			#pragma warning(default: 6320)
			if (should_attach) KeUnstackDetachProcess(&state);
			return _exception_code();
		}

		memcpy(buffer, kernel_buffer, buffer_size);
		ExFreePool(kernel_buffer);
		return status;
	}

	NTSTATUS fill_virtual_memory(void*& process_id, void*& base_address, const unsigned __int64& buffer_size, const int& value) noexcept
	{
		PEPROCESS process;
		const auto status = PsLookupProcessByProcessId(process_id, &process);
		if (!NT_SUCCESS(status))
		{
			return status;
		}

		const bool should_attach = legacy::should_attach(process_id);

		KAPC_STATE state;
		if (should_attach) KeStackAttachProcess(process, &state);

		__try
		{
			ProbeForWrite(base_address, buffer_size, sizeof(char));
			memset(base_address, value, buffer_size);
			if (should_attach) KeUnstackDetachProcess(&state);
		}
		// Handle any possible exceptions.
		#pragma warning(disable: 6320)
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			#pragma warning(default: 6320)
			if (should_attach) KeUnstackDetachProcess(&state);
			return _exception_code();
		}

		return status;
	}

	NTSTATUS zero_virtual_memory(void*& process_id, void*& base_address, const unsigned __int64& buffer_size) noexcept
	{
		return fill_virtual_memory(process_id, base_address, buffer_size, 0);
	}

	NTSTATUS allocate_virtual_memory(void*& process_id, void*& base_address, unsigned __int64& size,
		const unsigned int allocation_type, const unsigned int& protect) noexcept
	{
		void* handle;
		const auto status{ process::open_process_by_id(process_id, handle) };
		if (!NT_SUCCESS(status)) return status;

		return ZwAllocateVirtualMemory(handle, &base_address, 0, &size, allocation_type, protect);
	}

	NTSTATUS free_virtual_memory(void*& process_id, void*& base_address, unsigned __int64& size, const unsigned int free_type) noexcept
	{
		OBJECT_ATTRIBUTES attributes{};
		CLIENT_ID id{};
		id.UniqueProcess = process_id;

		void* handle;
		const auto status = ZwOpenProcess(&handle, PROCESS_ALL_ACCESS, &attributes, &id);
		if (!NT_SUCCESS(status))
		{
			return status;
		}

		return ZwFreeVirtualMemory(handle, &base_address, &size, free_type);
	}

	HANDLE secure_virtual_memory(void* process_id, void* address, size_t size, unsigned int probe_mode, unsigned int flags) noexcept
	{
		PEPROCESS process;
		const auto status = PsLookupProcessByProcessId(process_id, &process);
		if (!NT_SUCCESS(status)) { return nullptr; }

		const bool should_attach = legacy::should_attach(process_id);

		KAPC_STATE state;
		if (should_attach) { KeStackAttachProcess(process, &state); }

		__try
		{
			return MmSecureVirtualMemoryEx(address, size, probe_mode, flags);
		}
		__finally
		{
			if (should_attach) { KeUnstackDetachProcess(&state); }
			ObDereferenceObject(process);
			return nullptr;
		}
	}

	void unsecure_virtual_memory(void* process_id, void* address) noexcept
	{
		PEPROCESS process;
		const auto status = PsLookupProcessByProcessId(process_id, &process);
		if (!NT_SUCCESS(status)) return;

		const bool should_attach = legacy::should_attach(process_id);

		KAPC_STATE state;
		if (should_attach) KeStackAttachProcess(process, &state);

		MmUnsecureVirtualMemory(address);
		if (should_attach) KeUnstackDetachProcess(&state);
	}

	void free(void* address) noexcept
	{
		ExFreePoolWithTag(address, crt_pool_tag);
	}

	#pragma warning(disable: 28167)
	void enable_interrupt(KIRQL irql) noexcept
	{
		auto cr0 = __readcr0();
		cr0 |= 0x10000;
		_enable();
		__writecr0(cr0);
		KeLowerIrql(irql);
		KeLeaveGuardedRegion();
	}

	KIRQL disable_interrupt() noexcept
	{
		KeEnterGuardedRegion();
		const auto irql = KfRaiseIrql(HIGH_LEVEL);
		auto cr0 = __readcr0();
		cr0 &= ~(1 << 16);
		__writecr0(cr0);
		_disable();
		return irql;
	}
	#pragma warning(default: 28167)

	NTSTATUS read_physical_memory(void* destination, void* source, size_t size) noexcept
	{
		auto physical_address{ MmGetPhysicalAddress(source) };
		auto mapped_memory{ MmMapIoSpaceEx(physical_address, size, PAGE_READONLY) };
		if (mapped_memory)
		{
			memcpy(destination, mapped_memory, size);
			MmUnmapIoSpace(mapped_memory, size);
		}
		else
		{
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		return STATUS_SUCCESS;
	}

	NTSTATUS write_physical_memory(void* destination, void* source, size_t size) noexcept
	{
		auto physical_address{ MmGetPhysicalAddress(destination) };
		auto mapped_memory{ MmMapIoSpaceEx(physical_address, size, PAGE_READWRITE) };
		if (mapped_memory)
		{
			memcpy(mapped_memory, source, size);
			MmUnmapIoSpace(mapped_memory, size);
		}
		else
		{
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		return STATUS_SUCCESS;
	}

	NTSTATUS write_mdl_memory(void* destination, void* source, unsigned long size) noexcept
	{
		auto mdl{ IoAllocateMdl(destination, size, false, false, nullptr) };
		if (mdl == nullptr) return STATUS_INSUFFICIENT_RESOURCES;

		MmBuildMdlForNonPagedPool(mdl);
		const auto mdl_previous_flags{ mdl->MdlFlags };

		// Who are you to try and stop me modify mdl flags.
		#pragma warning(disable: __WARNING_MODIFYING_MDL)
		mdl->MdlFlags |= MDL_PAGES_LOCKED;
		mdl->MdlFlags &= ~MDL_SOURCE_IS_NONPAGED_POOL;
		const auto mapped{ MmMapLockedPagesSpecifyCache(mdl, MODE::KernelMode, MEMORY_CACHING_TYPE::MmCached, nullptr, false, MM_PAGE_PRIORITY::HighPagePriority) };
		if (mapped == nullptr)
		{
			mdl->MdlFlags = mdl_previous_flags;
			IoFreeMdl(mdl);
			return STATUS_NONE_MAPPED;
		}

		memcpy(mapped, source, size);
		MmUnmapLockedPages(mapped, mdl);
		mdl->MdlFlags = mdl_previous_flags;
		#pragma warning(default: __WARNING_MODIFYING_MDL)
		IoFreeMdl(mdl);
		return STATUS_SUCCESS;
	}

	NTSTATUS read_mdl_memory(void* destination, void* source, unsigned long size) noexcept
	{
		auto mdl{ IoAllocateMdl(destination, size, false, false, nullptr) };
		if (mdl == nullptr) return STATUS_INSUFFICIENT_RESOURCES;

		MmBuildMdlForNonPagedPool(mdl);

		// Why can't I modify mdl?
		#pragma warning(disable: __WARNING_MODIFYING_MDL)
		const auto mdl_previous_flags{ mdl->MdlFlags };
		mdl->MdlFlags |= MDL_PAGES_LOCKED;
		mdl->MdlFlags &= ~MDL_SOURCE_IS_NONPAGED_POOL;

		const auto mapped{ MmMapLockedPagesSpecifyCache(mdl, MODE::KernelMode, MEMORY_CACHING_TYPE::MmCached, nullptr, false, MM_PAGE_PRIORITY::HighPagePriority) };
		if (mapped == nullptr)
		{
			mdl->MdlFlags = mdl_previous_flags;
			IoFreeMdl(mdl);
			return STATUS_NONE_MAPPED;
		}

		memcpy(source, mapped, size);
		MmUnmapLockedPages(mapped, mdl);
		mdl->MdlFlags = mdl_previous_flags;
		#pragma warning(default: __WARNING_MODIFYING_MDL)
		IoFreeMdl(mdl);
		return STATUS_SUCCESS;
	}

	NTSTATUS read_physical_memory(void* process_id, void* base_address, void* buffer, size_t size) noexcept
	{
		PEPROCESS process;
		auto status = PsLookupProcessByProcessId(process_id, &process);
		if (!NT_SUCCESS(status))
		{
			return status;
		}

		auto kernel_buffer = legacy::allocate(size);
		if (kernel_buffer == nullptr)
		{

			// If ExAllocatePool returns null,
			// we should return the NTSTATUS value STATUS_INSUFFICIENT_RESOURCES
			// or should delay processing to another point in time.
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		const bool should_attach = legacy::should_attach(process_id);

		KAPC_STATE state;
		if (should_attach) KeStackAttachProcess(process, &state);

		__try
		{
			status = read_physical_memory(kernel_buffer, base_address, size);
			if (should_attach) KeUnstackDetachProcess(&state);
		}
		// Handle any possible exceptions.
		#pragma warning(disable: 6320)
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			#pragma warning(default: 6320)
			if (should_attach) KeUnstackDetachProcess(&state);
			return _exception_code();
		}

		memcpy(buffer, kernel_buffer, size);
		ExFreePool(kernel_buffer);
		return status;
	}

	NTSTATUS write_physical_memory(void* process_id, void* base_address, void* buffer, size_t size) noexcept
	{
		PEPROCESS process;
		auto status = PsLookupProcessByProcessId(process_id, &process);
		if (!NT_SUCCESS(status))
		{
			return status;
		}

		auto kernel_buffer = legacy::allocate(size);
		if (kernel_buffer == nullptr)
		{

			// If ExAllocatePool returns null,
			// we should return the NTSTATUS value STATUS_INSUFFICIENT_RESOURCES
			// or should delay processing to another point in time.
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		memcpy(kernel_buffer, buffer, size);

		const bool should_attach = legacy::should_attach(process_id);
		KAPC_STATE state;
		if (should_attach) KeStackAttachProcess(process, &state);

		__try
		{
			status = write_physical_memory(base_address, kernel_buffer, size);
			if (should_attach) KeUnstackDetachProcess(&state);
		}
		// Handle any possible exceptions.
		#pragma warning(disable: 6320)
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			#pragma warning(default: 6320)
			if (should_attach) KeUnstackDetachProcess(&state);

			return _exception_code();
		}

		ExFreePool(kernel_buffer);
		return status;
	}

	NTSTATUS write_mdl_memory(void* process_id, void* destination, void* source, unsigned long size) noexcept
	{
		PEPROCESS process;
		const auto status = PsLookupProcessByProcessId(process_id, &process);
		if (!NT_SUCCESS(status))
		{
			return status;
		}

		auto kernel_buffer = legacy::allocate(size);
		if (kernel_buffer == nullptr)
		{
			// If ExAllocatePool returns null,
			// we should return the NTSTATUS value STATUS_INSUFFICIENT_RESOURCES
			// or should delay processing to another point in time.

			return STATUS_INSUFFICIENT_RESOURCES;
		}

		memcpy(kernel_buffer, source, size);

		const bool should_attach = legacy::should_attach(process_id);
		KAPC_STATE state;
		if (should_attach) KeStackAttachProcess(process, &state);

		__try
		{
			write_mdl_memory(destination, kernel_buffer, size);
			if (should_attach) KeUnstackDetachProcess(&state);
		}
		// Handle any possible exceptions.
		#pragma warning(disable: 6320)
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			#pragma warning(default: 6320)
			if (should_attach) KeUnstackDetachProcess(&state);

			return _exception_code();
		}

		ExFreePool(kernel_buffer);
		return status;
	}

	NTSTATUS read_mdl_memory(void* process_id, void* destination, void* source, unsigned long size) noexcept
	{
		PEPROCESS process;
		const auto status = PsLookupProcessByProcessId(process_id, &process);
		if (!NT_SUCCESS(status))
		{
			return status;
		}

		auto kernel_buffer = legacy::allocate(size);
		if (kernel_buffer == nullptr)
		{

			// If ExAllocatePool returns null,
			// we should return the NTSTATUS value STATUS_INSUFFICIENT_RESOURCES
			// or should delay processing to another point in time.
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		const bool should_attach = legacy::should_attach(process_id);

		KAPC_STATE state;
		if (should_attach) KeStackAttachProcess(process, &state);

		__try
		{
			read_mdl_memory(destination, kernel_buffer, size);
			if (should_attach) KeUnstackDetachProcess(&state);
		}
		// Handle any possible exceptions.
		#pragma warning(disable: 6320)
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			#pragma warning(default: 6320)
			if (should_attach) KeUnstackDetachProcess(&state);
			return _exception_code();
		}

		memcpy(source, kernel_buffer, size);
		ExFreePool(kernel_buffer);
		return status;
	}

	void* allocate_contiguous(std::size_t size, bool zero) noexcept
	{
		PHYSICAL_ADDRESS maxium_address{};
		maxium_address.QuadPart = -1;
		auto address{ MmAllocateContiguousMemory(size, maxium_address) };
		if (address && zero) { RtlSecureZeroMemory(address, size); }

		return address;
	}

	void free_contiguous(void* address) noexcept
	{
		if (address) { MmFreeContiguousMemory(address); }
	}
}