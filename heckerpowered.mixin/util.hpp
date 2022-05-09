#pragma once
#include <ntifs.h>
#include "kernel_stl.hpp"
#include <vector>
#include "extern.hpp"
#include <string>
#include "lde.hpp"

#define println(format, ...) DbgPrintEx(DPFLTR_TYPE::DPFLTR_IHVDRIVER_ID,DPFLTR_ERROR_LEVEL,"[Mixins]: " format "\n",##__VA_ARGS__)

namespace util
{
	MODE set_previous_mode(MODE mode) noexcept;
	__int64 safe_find_string(const UNICODE_STRING& source, UNICODE_STRING& target, bool case_insensitive) noexcept;
	NTSTATUS safe_init_string(UNICODE_STRING& result, const UNICODE_STRING& source) noexcept;
	NTSTATUS safe_allocate_string(UNICODE_STRING& result, unsigned short size) noexcept;
	NTSTATUS execute_new_thread(void* base_address, void* parameter, unsigned long flags, bool wait, NTSTATUS& exit_status) noexcept;
	NTSTATUS pattern_scan(const unsigned char* pattern, unsigned char wildcard, std::size_t length, const void* base, std::size_t size, void*& found) noexcept;
	unsigned __int64 dereference(unsigned __int64 address, unsigned __int64 offset) noexcept;
}