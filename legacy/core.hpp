#pragma once

namespace core
{
	template <typename char_type>
	concept character = std::is_same_v<char_type, char> || std::is_same_v<char_type, wchar_t>;

	using index = std::ptrdiff_t;
}