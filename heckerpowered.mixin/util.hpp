#pragma once
#include <ntifs.h>
#include <vector>
#include <string>
#include "extern.hpp"
#include "lde.hpp"

#define println(format, ...) DbgPrintEx(DPFLTR_TYPE::DPFLTR_IHVDRIVER_ID,DPFLTR_ERROR_LEVEL,"[Mixins]: " format "\n",##__VA_ARGS__)

namespace util
{
	MODE set_previous_mode(MODE mode) noexcept;
	NTSTATUS pattern_scan(const unsigned char* pattern, unsigned char wildcard, std::size_t length, const void* base, std::size_t size, void*& found) noexcept;
}