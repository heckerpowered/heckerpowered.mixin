#include "pch.hpp"

namespace util
{
	MODE set_previous_mode(MODE mode) noexcept
	{
		static unsigned int previous_mode_offset = 0;
		if (previous_mode_offset == 0)
		{
			const auto ex_get_previous_mode{ reinterpret_cast<unsigned __int64>(ExGetPreviousMode) };
			const auto maxium{ ex_get_previous_mode + 20 };
			for (auto address{ ex_get_previous_mode }; address < maxium; address++)
			{
				if (MmIsAddressValid(reinterpret_cast<void*>(address)) && *reinterpret_cast<unsigned char*>(address) == 0x80 &&
					MmIsAddressValid(reinterpret_cast<void*>(address + 5)) && *reinterpret_cast<unsigned char*>(address + 5) == 0xC3)
				{
					previous_mode_offset = *reinterpret_cast<unsigned int*>(address + 1);
					break;
				}
			}
		}

		auto previous_mode = reinterpret_cast<MODE*>(PsGetCurrentThread()) + previous_mode_offset;

		const auto original_mode{ *previous_mode };
		*previous_mode = mode;
		return original_mode;
	}

	NTSTATUS pattern_scan(const unsigned char* pattern, unsigned char wildcard, std::size_t length, const void* base, std::size_t size, void*& found) noexcept
	{
		for (unsigned __int64 i{}; i < size - length; i++)
		{
			bool _found = true;
			for (unsigned __int64 j{}; j < length; j++)
			{
				if (pattern[j] != wildcard && pattern[j] != (reinterpret_cast<const unsigned char*>(base))[i + j])
				{
					_found = false;
					break;
				}
			}

			if (_found)
			{
				found = const_cast<void*>(reinterpret_cast<const void*>(reinterpret_cast<const unsigned char*>(base) + i));
				return STATUS_SUCCESS;
			}
		}

		return STATUS_NOT_FOUND;
	}

	KDDEBUGGER_DATA64& get_debugger_block() noexcept
	{
		CONTEXT context{ .ContextFlags = CONTEXT_FULL };
		RtlCaptureContext(&context);

		PDUMP_HEADER header{ static_cast<PDUMP_HEADER>(memory::allocate<POOL_FLAG_NON_PAGED>(0x40000)) };
		static KDDEBUGGER_DATA64 data{};

		if (data.KernBase != 0) { return data; }

		if (header)
		{
			KeCapturePersistentThreadState(&context, nullptr, 0, 0, 0, 0, 0, header);
			std::memcpy(&data, reinterpret_cast<char*>(header) + 0x2080, sizeof(data));
			memory::free(header);
		}

		return data;
	}
}