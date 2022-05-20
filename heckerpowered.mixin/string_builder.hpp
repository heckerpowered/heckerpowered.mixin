#pragma once

namespace core
{
	template<character char_type = char, typename...args_t>
	std::basic_string<char_type> connect(const args_t&... v)
	{
		std::basic_string<char_type> buffer;
		std::size_t length{};
		((length += std::basic_string_view<char_type>(v).size()), ...);
		buffer.reserve(length);
		((buffer += std::basic_string_view<char_type>(v)), ...);
		return buffer;
	}
}