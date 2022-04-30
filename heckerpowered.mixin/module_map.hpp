#pragma once
#include <ntifs.h>
#include <ntstrsafe.h>
#include "native_struct.hpp"
#include "file.hpp"
#include "extern.hpp"
#include "util.hpp"
#include "module.hpp"
#include "native.hpp"

namespace module::map{

    #define IMAGE32(hdr) (hdr->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
    #define IMAGE64(hdr) (hdr->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    
    #define HEADER_VAL_T(hdr, val) (IMAGE64(hdr) ? ((PIMAGE_NT_HEADERS64)hdr)->OptionalHeader.val : ((PIMAGE_NT_HEADERS32)hdr)->OptionalHeader.val)
    #define THUNK_VAL_T(hdr, ptr, val) (IMAGE64(hdr) ? ((PIMAGE_THUNK_DATA64)ptr)->val : ((PIMAGE_THUNK_DATA32)ptr)->val)
    #define TLS_VAL_T(hdr, ptr, val) (IMAGE64(hdr) ? ((PIMAGE_TLS_DIRECTORY64)ptr)->val : ((PIMAGE_TLS_DIRECTORY32)ptr)->val)
    #define CFG_DIR_VAL_T(hdr, dir, val) (IMAGE64(hdr) ? ((PIMAGE_LOAD_CONFIG_DIRECTORY64)dir)->val : ((PIMAGE_LOAD_CONFIG_DIRECTORY32)dir)->val)
    
    #if defined (_WIN10_)
    typedef PAPI_SET_VALUE_ENTRY_10     PAPISET_VALUE_ENTRY;
    typedef PAPI_SET_VALUE_ARRAY_10     PAPISET_VALUE_ARRAY;
    typedef PAPI_SET_NAMESPACE_ENTRY_10 PAPISET_NAMESPACE_ENTRY;
    typedef PAPI_SET_NAMESPACE_ARRAY_10 PAPISET_NAMESPACE_ARRAY;
    #elif defined (_WIN81_)
    typedef PAPI_SET_VALUE_ENTRY        PAPISET_VALUE_ENTRY;
    typedef PAPI_SET_VALUE_ARRAY        PAPISET_VALUE_ARRAY;
    typedef PAPI_SET_NAMESPACE_ENTRY    PAPISET_NAMESPACE_ENTRY;
    typedef PAPI_SET_NAMESPACE_ARRAY    PAPISET_NAMESPACE_ARRAY;
    #else
    typedef PAPI_SET_VALUE_ENTRY_V2     PAPISET_VALUE_ENTRY;
    typedef PAPI_SET_VALUE_ARRAY_V2     PAPISET_VALUE_ARRAY;
    typedef PAPI_SET_NAMESPACE_ENTRY_V2 PAPISET_NAMESPACE_ENTRY;
    typedef PAPI_SET_NAMESPACE_ARRAY_V2 PAPISET_NAMESPACE_ARRAY;
    #endif

    typedef struct _USER_CONTEXT
    {
        UCHAR code[0x1000];             // Code buffer
        union
        {
            UNICODE_STRING ustr;
            UNICODE_STRING32 ustr32;
        };
        wchar_t buffer[0x400];          // Buffer for unicode string


        // Activation context data
        union
        {
            ACTCTXW actx;
            ACTCTXW32 actx32;
        };
        HANDLE hCTX;
        ULONG hCookie;

        PVOID ptr;                      // Tmp data
        union
        {
            NTSTATUS status;            // Last execution status
            PVOID retVal;               // Function return value
            ULONG retVal32;             // Function return value
        };

        //UCHAR tlsBuf[0x100];
    } USER_CONTEXT,* PUSER_CONTEXT;

    typedef struct _MMAP_CONTEXT
    {
        PEPROCESS pProcess;     // Target process
        PVOID pWorkerBuf;       // Worker thread code buffer
        HANDLE hWorker;         // Worker thread handle
        PETHREAD pWorker;       // Worker thread object
        LIST_ENTRY modules;     // Manual module list
        PUSER_CONTEXT userMem;  // Tmp buffer in user space
        HANDLE hSync;           // APC sync handle
        PKEVENT pSync;          // APC sync object
        PVOID pSetEvent;        // ZwSetEvent address
        PVOID pLoadImage;       // LdrLoadDll address
        BOOLEAN tlsInitialized; // Static TLS was initialized
        BOOLEAN noThreads;      // No threads should be created
    } MMAP_CONTEXT,* PMMAP_CONTEXT;

    enum resolve_flags
    {
        api_shema_only = 1,
        skip_sxs = 2,
        full_path = 4,
    };

    NTSTATUS resolve_image_path(PMMAP_CONTEXT context, PEPROCESS process, resolve_flags flags, const UNICODE_STRING& path, const UNICODE_STRING& base_image,
        UNICODE_STRING& resolved) noexcept;

    NTSTATUS resolve_sxs(PMMAP_CONTEXT context, const UNICODE_STRING& name, PUNICODE_STRING resolved) noexcept;

    template<typename...Args> NTSTATUS call_routine(bool new_thread, PMMAP_CONTEXT context, void* routine, Args&& ... args) noexcept {
        std::vector<unsigned __int64> _args{args...};

        bool wow64(PsGetProcessWow64Process(context->pProcess));
        auto offset{ native::prologue(wow64, context->userMem->code) };
        offset += native::call(wow64, context->userMem->code + offset, routine, _args);
        offset += native::sync(wow64, context->userMem->code + offset, context->userMem->status, context->pSetEvent, context->pSync);
        offset += native::epilogue(wow64, context->userMem->code + offset, static_cast<int>(_args.size() * sizeof(unsigned long)));

        NTSTATUS status{};
        if (new_thread) {
            NTSTATUS exit_status;
            status = util::execute_new_thread(context->userMem->code, nullptr, 0 /*THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER*/, true, exit_status);
        }
        else {
            KeResetEvent(context->pSync);
            status = thread::queue_user_apc(context->pWorker, context->userMem->code, nullptr, nullptr, nullptr, context->noThreads);
            if (NT_SUCCESS(status)) {
                LARGE_INTEGER timeout{};
                timeout.QuadPart = -(10ll * 10 * 1000 * 1000);  // 10s

                status = KeWaitForSingleObject(context->pSync, KWAIT_REASON::Executive, MODE::UserMode, true, &timeout);

                timeout.QuadPart = -(1ll * 10 * 1000);          // 1ms
                KeDelayExecutionThread(KernelMode, TRUE, &timeout);
            }
        }

        return status;
    }
}