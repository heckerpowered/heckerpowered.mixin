#include "string_builder.hpp"

namespace core
{
	std::string connect(std::initializer_list<std::string>&& v) noexcept
	{
		std::string result;
		result.resize(std::accumulate(v.begin(), v.end(), std::size_t{}, [](std::size_t size, const std::string& string) { return size + string.size(); }));
		static_cast<void>(std::accumulate(v.begin(), v.end(), result.begin(), [](const auto& destination, const std::string& source)
		{
			return std::copy(source.cbegin(), source.cend(), destination);
		}));
		return result;
	}

	std::wstring connect(std::initializer_list<std::wstring>&& v) noexcept
	{
		std::wstring result;
		result.resize(std::accumulate(v.begin(), v.end(), std::size_t{}, [](std::size_t size, const std::wstring& string) { return size + string.size(); }));
		static_cast<void>(std::accumulate(v.begin(), v.end(), result.begin(), [](const auto& destination, const std::wstring& source)
		{
			return std::copy(source.cbegin(), source.cend(), destination);
		}));
		return result;
	}
}