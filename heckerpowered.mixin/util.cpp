#include "util.hpp"

namespace util
{
	MODE set_previous_mode(MODE mode) noexcept
	{
		static unsigned int previous_mode_offset = 0;
		if (previous_mode_offset == 0)
		{
			auto ex_get_previous_mode{ reinterpret_cast<unsigned __int64>(ExGetPreviousMode) };
			auto maxium{ ex_get_previous_mode + 20 };
			for (auto address{ ex_get_previous_mode }; address < maxium; address++)
			{
				if (MmIsAddressValid(reinterpret_cast<void*>(address)) && *reinterpret_cast<unsigned char*>(address) == 0x80 &&
					MmIsAddressValid(reinterpret_cast<void*>(address + 5)) && *reinterpret_cast<unsigned char*>(address + 5) == 0xC3)
				{
					previous_mode_offset = *reinterpret_cast<unsigned int*>(address + 1);
					break;
				}
			}
		}

		auto previous_mode = reinterpret_cast<MODE*>(PsGetCurrentThread()) + previous_mode_offset;

		MODE original_mode = *previous_mode;
		*previous_mode = mode;
		return original_mode;
	}

	__int64 safe_find_string(const UNICODE_STRING& source, UNICODE_STRING& target, bool case_insensitive) noexcept
	{
		if (source.Buffer == nullptr || target.Buffer == nullptr) return -1;
		if (source.Length < target.Length) return -1;

		unsigned short difference(source.Length - target.Length);
		unsigned short maxium{ difference / sizeof(wchar_t) };
		for (unsigned short i{}; i <= maxium; i++)
			if (RtlCompareUnicodeStrings(source.Buffer + i, target.Length / sizeof(wchar_t),
				target.Buffer, target.Length / sizeof(wchar_t), case_insensitive) == 0) return i;

		return -1;
	}

	NTSTATUS safe_init_string(UNICODE_STRING& result, const UNICODE_STRING& source) noexcept
	{
		if (source.Buffer == nullptr) return STATUS_INVALID_PARAMETER;

		if (source.Length == 0)
		{
			result.Length = result.MaximumLength = 0;
			result.Buffer = nullptr;
			return STATUS_SUCCESS;
		}

		result.Buffer = reinterpret_cast<wchar_t*>(memory::allocate<POOL_TYPE::PagedPool>(source.MaximumLength, false));
		result.Length = source.Length;
		result.MaximumLength = source.MaximumLength;
		memcpy(result.Buffer, source.Buffer, source.Length);

		return STATUS_SUCCESS;
	}

	NTSTATUS safe_allocate_string(UNICODE_STRING& result, unsigned short size) noexcept
	{
		if (size == 0) return STATUS_INVALID_PARAMETER;

		result.Buffer = reinterpret_cast<wchar_t*>(memory::allocate<POOL_TYPE::PagedPool>(size));
		if (result.Buffer == nullptr) return STATUS_INSUFFICIENT_RESOURCES;

		result.Length = 0;
		result.MaximumLength = size;
		return STATUS_SUCCESS;
	}

	NTSTATUS pattern_scan(const unsigned char* pattern, unsigned char wildcard, std::size_t length, const void* base, std::size_t size, void*& found) noexcept
	{
		for (unsigned __int64 i{}; i < size - length; i++)
		{
			bool _found = true;
			for (unsigned __int64 j{}; j < length; j++)
			{
				if (pattern[j] != wildcard && pattern[j] != (reinterpret_cast<const unsigned char*>(base))[i + j])
				{
					_found = false;
					break;
				}
			}

			if (_found)
			{
				found = const_cast<void*>(reinterpret_cast<const void*>(reinterpret_cast<const unsigned char*>(base) + i));
				return STATUS_SUCCESS;
			}
		}

		return STATUS_NOT_FOUND;
	}

	NTSTATUS execute_new_thread(void* base_address, void* parameter, unsigned long flags, bool wait, NTSTATUS& exit_status) noexcept
	{
		OBJECT_ATTRIBUTES object_attributes{};
		InitializeObjectAttributes(&object_attributes, nullptr, OBJ_KERNEL_HANDLE, nullptr, nullptr);

		HANDLE thread{};
		auto status{ ZwCreateThreadEx(&thread, THREAD_QUERY_LIMITED_INFORMATION, &object_attributes, ZwCurrentProcess(), base_address, parameter, flags,
			0, 0x1000, 0x100000, nullptr) };

		if (!NT_SUCCESS(status)) { return status; }

		if (wait)
		{
			status = ZwWaitForSingleObject(thread, true, nullptr);
			if (NT_SUCCESS(status))
			{
				THREAD_BASIC_INFORMATION info{};
				status = ZwQueryInformationThread(thread, ThreadBasicInformation, &info, sizeof(info), nullptr);
				if (NT_SUCCESS(status)) { exit_status = info.ExitStatus; }
			}
		}

		status = ZwClose(thread);
		return status;
	}

	unsigned __int64 dereference(unsigned __int64 address, unsigned __int64 offset) noexcept
	{
		if (address == 0) { return 0; }

		return address + static_cast<unsigned __int64>(*reinterpret_cast<unsigned __int64*>(address + offset) + offset + sizeof(int));
	}
}