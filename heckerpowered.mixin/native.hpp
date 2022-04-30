#pragma once
#include <ntifs.h>
#include "memory.hpp"
#include <vector>

namespace native {
	unsigned long prologue32(unsigned char* buffer) noexcept;
	unsigned long epilogue32(unsigned char* buffer, int ret_size) noexcept;
	unsigned long call32(unsigned char* buffer, void* function, const std::vector<unsigned long>& args) noexcept;
	unsigned long sync32(unsigned char* buffer, NTSTATUS& status, void* set_event, HANDLE event) noexcept;

	unsigned long prologue64(unsigned char* buffer) noexcept;
	unsigned long epilogue64(unsigned char* buffer, int ret_size [[maybe_unused]]) noexcept;
	unsigned long call64(unsigned char* buffer, void* function, const std::vector<unsigned __int64>& args) noexcept;
	unsigned long sync64(unsigned char* buffer, NTSTATUS& status, void* set_event, HANDLE event) noexcept;

	unsigned long prologue(bool wow64, unsigned char* buffer) noexcept;
	unsigned long epilogue(bool wow64, unsigned char* buffer, int ret_size) noexcept;
	unsigned long call(bool wow64, unsigned char* buffer, void* function, const std::vector<unsigned __int64>& args) noexcept;
	unsigned long sync(bool wow64, unsigned char* buffer, NTSTATUS& status, void* set_event, HANDLE event) noexcept;
}