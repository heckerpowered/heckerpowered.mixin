// C++ 20 stl support in kernel-mode.

#pragma once
#include <ntifs.h>
#define ceilf _ceilf
// float support
#pragma comment(lib,"libcntpr.lib")
extern "C" __declspec(selectany) int _fltused = 0;

#define NOMINMAX
#undef min
#undef max
#undef _HAS_EXCEPTIONS
#undef _HAS_STATIC_RTTI
// This enables use of STL in kernel-mode.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-macros"
#define _HAS_EXCEPTIONS 0
#define _HAS_STATIC_RTTI 0
#pragma clang diagnostic pop
#pragma prefast(disable : 30030)
#pragma warning(disable: 4595)
#pragma warning(disable: 28301)
#pragma warning(disable: 28250)
#pragma warning(disable: 28251)
#pragma warning(disable: 28252)
#pragma warning(disable: 28253)
/// A pool tag for this module
static constexpr ULONG kKstlpPoolTag = 'LTSK';

DECLSPEC_NORETURN static void KernelStlpRaiseException(
    _In_ ULONG bug_check_code) {
    __debugbreak();
    #pragma warning(push)
    #pragma warning(disable : 28159)
    KeBugCheck(bug_check_code);
    #pragma warning(pop)
}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-prototypes"

DECLSPEC_NORETURN inline void __cdecl _invalid_parameter_noinfo_noreturn() {
    KernelStlpRaiseException(KMODE_EXCEPTION_NOT_HANDLED);
}

extern "C" inline float _ceilf(float _X) {
    return (float)(int)(_X + 1);
}

extern "C" inline __declspec(noreturn) void __cdecl abort(void) {
    KernelStlpRaiseException(KMODE_EXCEPTION_NOT_HANDLED);
}

extern "C" __declspec(noreturn) inline void __cdecl
_invoke_watson(
    wchar_t const* const expression [[maybe_unused]],
    wchar_t const* const function_name [[maybe_unused]],
    wchar_t const* const file_name [[maybe_unused]],
    unsigned int   const line_number [[maybe_unused]],
    uintptr_t      const reserved [[maybe_unused]] ) {
    KernelStlpRaiseException(KMODE_EXCEPTION_NOT_HANDLED);
}

#include <exception>
__declspec(selectany) void(__cdecl* std::_Raise_handler)(const std::exception&);

namespace std {
    DECLSPEC_NORETURN inline void __cdecl _Xbad_function_call() {
        KernelStlpRaiseException(KMODE_EXCEPTION_NOT_HANDLED);
    }

    inline DECLSPEC_NORETURN void __cdecl _Xbad_alloc() {
        KernelStlpRaiseException(KMODE_EXCEPTION_NOT_HANDLED);
    }
    inline DECLSPEC_NORETURN void __cdecl _Xinvalid_argument(_In_z_ const char*) {
        KernelStlpRaiseException(KMODE_EXCEPTION_NOT_HANDLED);
    }
    inline DECLSPEC_NORETURN void __cdecl _Xlength_error(_In_z_ const char*) {
        KernelStlpRaiseException(KMODE_EXCEPTION_NOT_HANDLED);
    }
    inline DECLSPEC_NORETURN void __cdecl _Xout_of_range(_In_z_ const char*) {
        KernelStlpRaiseException(KMODE_EXCEPTION_NOT_HANDLED);
    }
    inline DECLSPEC_NORETURN void __cdecl _Xoverflow_error(_In_z_ const char*) {
        KernelStlpRaiseException(KMODE_EXCEPTION_NOT_HANDLED);
    }
    inline DECLSPEC_NORETURN void __cdecl _Xruntime_error(_In_z_ const char*) {
        KernelStlpRaiseException(KMODE_EXCEPTION_NOT_HANDLED);
    }
}  // namespace std

// An alternative implementation of the new operator
_IRQL_requires_max_(DISPATCH_LEVEL) inline void* __cdecl operator new(
    _In_ size_t size) {
    if (size == 0) {
        size = 1;
    }

    const auto p = ExAllocatePool2(POOL_FLAG_NON_PAGED, size, kKstlpPoolTag);
    if (!p) {
        KernelStlpRaiseException(MUST_SUCCEED_POOL_EMPTY);
    }
    return p;
}

// An alternative implementation of the new operator
_IRQL_requires_max_(DISPATCH_LEVEL) inline void __cdecl operator delete(_In_ void* p) {
    if (p) {
        ExFreePoolWithTag(p, kKstlpPoolTag);
    }
}

// An alternative implementation of the new operator
_IRQL_requires_max_(DISPATCH_LEVEL) inline void __cdecl operator delete(
    _In_ void* p, _In_ size_t size) {
    UNREFERENCED_PARAMETER(size);
    if (p) {
        ExFreePoolWithTag(p, kKstlpPoolTag);
    }
}

// overload new[] and delete[] operator
_IRQL_requires_max_(DISPATCH_LEVEL) inline void* __cdecl operator new[](
    _In_ size_t size) {
    if (size == 0) {
        size = 1;
    }

    const auto p = ExAllocatePool2(POOL_FLAG_NON_PAGED, size, kKstlpPoolTag);
    if (!p) {
        KernelStlpRaiseException(MUST_SUCCEED_POOL_EMPTY);
    }
    return p;
}

_IRQL_requires_max_(DISPATCH_LEVEL) inline void __cdecl operator delete[](
    _In_ void* p) {
    if (p) {
        ExFreePoolWithTag(p, kKstlpPoolTag);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL) inline void __cdecl operator delete[](
    _In_ void* p, _In_ size_t size) {
    UNREFERENCED_PARAMETER(size);
    if (p) {
        ExFreePoolWithTag(p, kKstlpPoolTag);
    }
}

#pragma clang diagnostic pop

constexpr unsigned long crt_pool_tag = 'TRC_';

using _PVFV = void(__cdecl*)(void); // PVFV = Pointer to Void Func(Void)
using _PIFV = int(__cdecl*)(void); // PIFV = Pointer to Int Func(Void)

constexpr int max_destructors_count = 64;
static _PVFV onexitarray[max_destructors_count] = {};
static _PVFV* onexitbegin = nullptr, * onexitend = nullptr;

// C initializers:
#pragma section(".CRT$XIA", long, read)
__declspec(selectany) __declspec(allocate(".CRT$XIA")) _PIFV __xi_a[] = { 0 };
#pragma section(".CRT$XIZ", long, read)
__declspec(selectany) __declspec(allocate(".CRT$XIZ")) _PIFV __xi_z[] = { 0 };

// C++ initializers:
#pragma section(".CRT$XCA", long, read)
__declspec(selectany) __declspec(allocate(".CRT$XCA")) _PVFV __xc_a[] = { 0 };
#pragma section(".CRT$XCZ", long, read)
__declspec(selectany) __declspec(allocate(".CRT$XCZ")) _PVFV __xc_z[] = { 0 };

// C pre-terminators:
#pragma section(".CRT$XPA", long, read)
__declspec(selectany) __declspec(allocate(".CRT$XPA")) _PVFV __xp_a[] = { 0 };
#pragma section(".CRT$XPZ", long, read)
__declspec(selectany) __declspec(allocate(".CRT$XPZ")) _PVFV __xp_z[] = { 0 };

// C terminators:
#pragma section(".CRT$XTA", long, read)
__declspec(selectany) __declspec(allocate(".CRT$XTA")) _PVFV __xt_a[] = { 0 };
#pragma section(".CRT$XTZ", long, read)
__declspec(selectany) __declspec(allocate(".CRT$XTZ")) _PVFV __xt_z[] = { 0 };

#pragma data_seg()

#pragma comment(linker, "/merge:.CRT=.rdata")

extern "C" inline int __cdecl __init_on_exit_array()
{
    onexitend = onexitbegin = onexitarray;
    *onexitbegin = 0;
    return 0;
}

extern "C" inline int __cdecl atexit(_PVFV fn)
{
    // ToDo: replace with dynamically allocated list of destructors!
    if (onexitend > &onexitarray[max_destructors_count - 1])
        return 1; // Not enough space

    *onexitend = fn;
    onexitend++;
    return 0;
}

inline int __cdecl _purecall()
{
    // It's abnormal execution, so we should to detect it:
    __debugbreak();
    return 0;
}

static inline void execute_pvfv_array(_PVFV* begin, _PVFV* end)
{
    _PVFV* fn = begin;
    while (fn != end)
    {
        if (*fn) (**fn)();
        ++fn;
    }
}

static inline int execute_pifv_array(_PIFV* begin, _PIFV* end)
{
    _PIFV* fn = begin;
    while (fn != end)
    {
        if (*fn)
        {
            const int result = (**begin)();
            if (result)
                return result;
        }
        ++fn;
    }
    return 0;
}

extern "C" inline int __crt_init()
{
    __init_on_exit_array();

   const int result = execute_pifv_array(__xi_a, __xi_z);
    if (result)
        return result;

    execute_pvfv_array(__xc_a, __xc_z);
    return 0;
}

extern "C" inline void __crt_deinit()
{
    if (onexitbegin)
    {
        while (--onexitend >= onexitbegin)
            if (*onexitend != 0) (**onexitend)();
    }
    execute_pvfv_array(__xp_a, __xp_z);
    execute_pvfv_array(__xt_a, __xt_z);
}
#pragma warning(default: 4595)
#pragma warning(default: 28301)
#pragma warning(default: 28250)
#pragma warning(default: 28251)
#pragma warning(default: 28252)
#pragma warning(default: 28253)

#ifdef __cplusplus
extern "C" {
    #endif
    __declspec(selectany) int __fltused = 0;
    #ifdef __cplusplus
}
#endif