#pragma once

namespace core
{
	template<typename T> concept iec559 = std::numeric_limits<T>::is_iec559;
	template<typename T> concept boolean = std::is_same_v<bool, std::decay_t<T>>;

	template<std::convertible_to<std::basic_string_view<char>> T, character char_type = char>
	[[nodiscard]] inline std::basic_string<char_type> to_string(const T& value) noexcept
	{
		return std::basic_string<char_type>{ value };
	}

	template<character char_type = char, iec559 T>
	[[nodiscard]] inline std::basic_string<char_type> to_string(const T value) noexcept
	{
		if constexpr (std::is_same_v<char_type, char>)
		{
			return std::to_string(value);
		}
		else
		{
			return std::to_wstring(value);
		}
	}

	template<character char_type = char, std::integral T, typename = std::enable_if_t<!std::is_same_v<std::decay_t<T>, bool>>>
	[[nodiscard]] inline std::basic_string<char_type> to_string(const T value) noexcept
	{
		if constexpr (std::is_same_v<char_type, char>)
		{
			return std::to_string(value);
		}
		else
		{
			return std::to_wstring(value);
		}
	}

	template<character char_type = char, boolean T>
	[[nodiscard]] constexpr std::basic_string<char_type> to_string(const T value) noexcept
	{
		if constexpr (std::is_same_v<char_type, char>)
		{
			return value ? "True" : "False";
		}
		else
		{
			return value ? L"True" : L"False";
		}
	}

	template<character char_type = char>
	[[nodiscard]] constexpr std::basic_string<char_type>&& to_string(std::basic_string<char_type>&& value) noexcept
	{
		return std::forward<std::basic_string<char_type>>(value);
	}

	template<character char_type = char>
	[[nodiscard]] inline const std::basic_string<char_type>& to_string(const std::basic_string<char_type>& value) noexcept
	{
		return value;
	}

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

	template<character char_type = char, typename...args_t>
	[[nodiscard]] std::basic_string<char_type> concat(const args_t&... v)
	{
		return connect(to_string(v)...);
	}
}