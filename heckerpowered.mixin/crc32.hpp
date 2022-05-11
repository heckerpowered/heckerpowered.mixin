#pragma once

#include <string>

namespace crc32
{
	const unsigned int compute(void* buffer, std::size_t length) noexcept;
}