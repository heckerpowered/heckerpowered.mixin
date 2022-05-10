#pragma once
#include <string>
#include <memory>
#include <algorithm>
#include <numeric>

namespace core
{
	std::string connect(std::initializer_list<std::string>&& v) noexcept;
	std::wstring connect(std::initializer_list<std::wstring>&& v) noexcept;
}