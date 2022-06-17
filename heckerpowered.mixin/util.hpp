#pragma once

namespace util
{
	MODE set_previous_mode(MODE mode) noexcept;
	NTSTATUS pattern_scan(const unsigned char* pattern, unsigned char wildcard, std::size_t length, const void* base, std::size_t size, void*& found) noexcept;
	KDDEBUGGER_DATA64& get_debugger_block() noexcept;
}