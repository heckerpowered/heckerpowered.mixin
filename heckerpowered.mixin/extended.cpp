#include "extended.hpp"

namespace virtualization::extended
{
	Eptp extended_page_table_pointer{};
	char* extended_page;

	bool initialize() noexcept
	{
		extended_page = reinterpret_cast<char*>(memory::allocate((2 + memory_size + memory_size * 512) * PAGE_SIZE));
		if (extended_page == nullptr) { return false; }

		auto page_map_level_4{ reinterpret_cast<unsigned __int64*>(extended_page + (memory_size + memory_size * 512) * PAGE_SIZE) };
		auto page_directory_pointer_table{ reinterpret_cast<unsigned __int64*>(extended_page + (1 + memory_size + memory_size * 512) * PAGE_SIZE) };

		page_map_level_4[0] = MmGetPhysicalAddress(page_directory_pointer_table).QuadPart + 7;

		unsigned __int64 index{};
		for (unsigned __int64 page_directory_pointer_table_index{}; page_directory_pointer_table_index < memory_size; page_directory_pointer_table_index++)
		{
			auto page_directory_table{ reinterpret_cast<unsigned __int64*>(extended_page + PAGE_SIZE * index++) };
			page_directory_pointer_table[page_directory_pointer_table_index] = MmGetPhysicalAddress(page_directory_table).QuadPart + 7;
			for (unsigned __int64 page_directory_table_index{}; page_directory_table_index < 512; page_directory_table_index++)
			{
				auto page_table{ reinterpret_cast<unsigned __int64*>(extended_page + PAGE_SIZE * index++) };
				page_directory_table[page_directory_pointer_table_index] = MmGetPhysicalAddress(page_table).QuadPart + 7;

				for (unsigned __int64 page_table_index{}; page_table_index < 512; page_table_index++)
				{
					page_table[page_table_index] = (page_directory_pointer_table_index * (1 << 30) + page_directory_table_index * (1 << 24) 
						+ page_table_index * (1 << 12) + 0x37);
				}
			}
		}

		extended_page_table_pointer.all = MmGetPhysicalAddress(page_map_level_4).QuadPart + 7;
		const unsigned __int64 memory_type{ __readmsr(MSR::MsrVmxEptVpidCap) & 0x100 };
		extended_page_table_pointer.fields.memory_type = memory_type ? 0 : 6;
		extended_page_table_pointer.fields.page_walk_length = 3;
		return true;
	}

	EptCommonEntry* get_page_table_entry(unsigned __int64 physical_address) noexcept
	{
		#ifdef FANCY
		return reinterpret_cast<EptCommonEntry*>(reinterpret_cast<unsigned __int64*>(extended_page + (((memory_size + memory_size * 512) / 513) *
			(physical_address >> (9 + 9 + 12)) & 0x1FF + (physical_address >> (9 + 12)) & 0x1FF + 1) * PAGE_SIZE) + ((physical_address >> 12) & 0x1FF));
		#endif

		const auto page_directory_pointer_table_index{ (physical_address >> (9 + 9 + 12)) & 0x1FF };
		const auto page_directory_table_index{ (physical_address >> (9 + 12)) & 0x1FF };
		const auto page_table_index{ (physical_address >> 12) & 0x1FF };

		unsigned __int64 offset{ (memory_size + memory_size * 512) / 513 };
		offset *= page_directory_pointer_table_index;
		offset += page_directory_table_index + 1;

		return reinterpret_cast<EptCommonEntry*>(reinterpret_cast<unsigned __int64*>(extended_page + offset * PAGE_SIZE) + page_table_index);
	}
}