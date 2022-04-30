#include "concurrent.hpp"

namespace concurrent
{
	void interlocked_copy(void* destination, const void* source, std::size_t length) noexcept
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