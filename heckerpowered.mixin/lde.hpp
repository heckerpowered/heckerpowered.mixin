#pragma once
#include "memory.hpp"

namespace lde
{
	void initialize() noexcept;
	int lde(void* p, int dw) noexcept;
}