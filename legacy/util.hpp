#pragma once

namespace util
{
	MODE const set_previous_mode(MODE const mode) noexcept;
	NTSTATUS const pattern_scan(unsigned char const* pattern, unsigned char wildcard, std::size_t length, const void* base, std::size_t size, void*& found) noexcept;
	KDDEBUGGER_DATA64 const& get_debugger_block() noexcept;
}