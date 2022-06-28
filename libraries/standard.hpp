#pragma once
#include <ntddk.h>
#include <cstddef>
#include <exception>
#include <vcruntime_new.h>
static constexpr unsigned long pool_flag = 'LTSK';

//
// non-member operator new or delete functions may not be declared inline
//
#pragma warning(disable: 4595)

_IRQL_requires_max_(DISPATCH_LEVEL)
inline void __cdecl operator delete(_Pre_notnull_ __drv_freesMem(Mem) void* p) noexcept
{
	if (p)
	{
		ExFreePoolWithTag(p, pool_flag);
	}
}

_IRQL_requires_max_(DISPATCH_LEVEL)
inline void __cdecl operator delete(_Pre_notnull_ __drv_freesMem(Mem) void* p, _In_ std::size_t) noexcept
{
	if (p)
	{
		ExFreePoolWithTag(p, pool_flag);
	}
}

[[noreturn]] _declspec(noreturn) static void kernel_raise_exception(unsigned long const bug_check_code) noexcept
{
#pragma warning(disable : __WARNING_USE_OTHER_FUNCTION)
	KeBugCheck(bug_check_code);
#pragma warning(default : __WARNING_USE_OTHER_FUNCTION)
}

[[nodiscard]] 
_Ret_notnull_ 
_Post_writable_byte_size_(size)
__drv_allocatesMem(Mem)
_Ret_notnull_
_IRQL_requires_max_(APC_LEVEL)
__declspec(allocator) 
__declspec(restrict)
inline void* __cdecl operator new(std::size_t size)
{
	if (size == 0) [[unlikely]]
	{
		size = 1;
	}

	auto const p = ExAllocatePool2(POOL_FLAG_NON_PAGED, size, pool_flag);
	if (p == nullptr)
	{
		kernel_raise_exception(MUST_SUCCEED_POOL_EMPTY);
	}

	return p;
}

#pragma warning(default: 4595)

inline __declspec(noreturn) void __cdecl _invalid_parameter_noinfo_noreturn()
{
	kernel_raise_exception(KMODE_EXCEPTION_NOT_HANDLED);
}

__declspec(noreturn) _ACRTIMP inline void __cdecl _invoke_watson(_In_opt_z_ wchar_t const* const expression [[maybe_unused]], 
	_In_opt_z_ wchar_t const* const function_name [[maybe_unused]], _In_opt_z_ wchar_t const* const file_name [[maybe_unused]], 
	_In_ unsigned int const line_number [[maybe_unused]], _In_ uintptr_t const reserved [[maybe_unused]] )
{
	kernel_raise_exception(KMODE_EXCEPTION_NOT_HANDLED);
}

namespace std
{
	[[noreturn]] __declspec(noreturn) inline void __cdecl _Xbad_function_call() noexcept
	{
		kernel_raise_exception(KMODE_EXCEPTION_NOT_HANDLED);
	}

	[[noreturn]] __declspec(noreturn) inline void __cdecl _Xbad_alloc() noexcept
	{
		kernel_raise_exception(KMODE_EXCEPTION_NOT_HANDLED);
	}

	[[noreturn]] __declspec(noreturn) inline void __cdecl _Xinvalid_argument(_In_z_ char const*) noexcept
	{
		kernel_raise_exception(KMODE_EXCEPTION_NOT_HANDLED);
	}

	[[noreturn]] __declspec(noreturn) inline void __cdecl _Xlength_error(_In_z_ char const*) noexcept
	{
		kernel_raise_exception(KMODE_EXCEPTION_NOT_HANDLED);
	}

	[[noreturn]] __declspec(noreturn) inline void __cdecl _Xout_of_range(_In_z_ char const*) noexcept
	{
		kernel_raise_exception(KMODE_EXCEPTION_NOT_HANDLED);
	}

	[[noreturn]] __declspec(noreturn) inline void __cdecl _Xoverflow_error(_In_z_ char const*) noexcept
	{
		kernel_raise_exception(KMODE_EXCEPTION_NOT_HANDLED);
	}

	[[noreturn]] __declspec(noreturn) inline void __cdecl _Xruntime_error(_In_z_ char const*) noexcept
	{
		kernel_raise_exception(KMODE_EXCEPTION_NOT_HANDLED);
	}
}