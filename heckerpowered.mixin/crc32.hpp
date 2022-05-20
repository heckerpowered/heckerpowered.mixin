#pragma once

namespace crc32
{
	const unsigned int compute(void* buffer, std::size_t length) noexcept;
}