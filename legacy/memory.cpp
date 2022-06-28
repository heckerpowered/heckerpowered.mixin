#include "pch.hpp"

namespace memory
{
	std::uint64_t attach(HANDLE process_id) noexcept
	{
		PEPROCESS process{};
		auto status{ PsLookupProcessByProcessId(process_id, &process) };
		if (!NT_SUCCESS(status)) { return 0; }

		auto nt_process{ reinterpret_cast<PNT_KPROCESS>(process) };
		auto guest_cr3{ nt_process->DirectoryTableBase };
		auto previous_cr3{ __readcr3() };
		__writecr3(guest_cr3);
		ObDereferenceObject(process);
		return previous_cr3;
	}

	PHYSICAL_ADDRESS virtual_address_to_physical_address_by_process_id(void* virtual_address, HANDLE process_id) noexcept
	{
		auto cr3{ attach(process_id) };
		if (cr3 == 0) { return {}; }

		auto physical_address{ MmGetPhysicalAddress(virtual_address) };
		__writecr3(cr3);
		return physical_address;
	}

	NTSTATUS read_process_memory(HANDLE process_id, void* address, bool is_physical, void* user_buffer, std::size_t size, std::size_t& return_size) noexcept
	{
		if (PsGetCurrentProcessId() != process_id && !is_physical)
		{
			return MmCopyMemory(user_buffer, { .PhysicalAddress = virtual_address_to_physical_address_by_process_id(address, process_id) },
				size, MM_COPY_MEMORY_PHYSICAL, &return_size);
		}
		else
		{
			if (is_physical)
			{
				return MmCopyMemory(user_buffer, { address }, size, MM_COPY_MEMORY_PHYSICAL, &return_size);
			}
			else
			{
				return MmCopyMemory(user_buffer, { address }, size, MM_COPY_MEMORY_VIRTUAL, &return_size);
			}
		}
	}
}