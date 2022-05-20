#pragma once

#define MM_ZERO_ACCESS         0
#define MM_READONLY            1
#define MM_EXECUTE             2
#define MM_EXECUTE_READ        3
#define MM_READWRITE           4
#define MM_WRITECOPY           5
#define MM_EXECUTE_READWRITE   6
#define MM_EXECUTE_WRITECOPY   7

#define MM_PTE_VALID_MASK         0x1
#define MM_PTE_WRITE_MASK         0x800
#define MM_PTE_OWNER_MASK         0x4
#define MM_PTE_WRITE_THROUGH_MASK 0x8
#define MM_PTE_CACHE_DISABLE_MASK 0x10
#define MM_PTE_ACCESS_MASK        0x20
#define MM_PTE_DIRTY_MASK         0x42
#define MM_PTE_LARGE_PAGE_MASK    0x80
#define MM_PTE_GLOBAL_MASK        0x100
#define MM_PTE_COPY_ON_WRITE_MASK 0x200
#define MM_PTE_PROTOTYPE_MASK     0x400
#define MM_PTE_TRANSITION_MASK    0x800

#define VIRTUAL_ADDRESS_BITS 48
#define VIRTUAL_ADDRESS_MASK ((((ULONG_PTR)1) << VIRTUAL_ADDRESS_BITS) - 1)

#define THREAD_CREATE_FLAGS_CREATE_SUSPENDED        0x00000001
#define THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH      0x00000002
#define THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER      0x00000004

#define MI_SYSTEM_RANGE_START (ULONG_PTR)(0xFFFF080000000000) // start of system space

#define EX_ADDITIONAL_INFO_SIGNATURE (ULONG_PTR)(-2)

#define KI_USER_SHARED_DATA 0xFFFFF78000000000UI64

#define SharedUserData ((KUSER_SHARED_DATA * const)KI_USER_SHARED_DATA)

#ifndef PTE_SHIFT
#define PTE_SHIFT 3
#endif
#ifndef PTI_SHIFT
#define PTI_SHIFT 12
#endif
#ifndef PDI_SHIFT
#define PDI_SHIFT 21
#endif
#ifndef PPI_SHIFT
#define PPI_SHIFT 30
#endif
#ifndef PXI_SHIFT
#define PXI_SHIFT 39
#endif

#ifndef PXE_BASE
#define PXE_BASE    0xFFFFF6FB7DBED000UI64
#endif
#ifndef PXE_SELFMAP
#define PXE_SELFMAP 0xFFFFF6FB7DBEDF68UI64
#endif
#ifndef PPE_BASE
#define PPE_BASE    0xFFFFF6FB7DA00000UI64
#endif
#ifndef PDE_BASE
#define PDE_BASE    0xFFFFF6FB40000000UI64
#endif
#ifndef PTE_BASE
#define PTE_BASE    0xFFFFF68000000000UI64
#endif

#ifndef _WIN64
#define KDDEBUGGER_DATA_OFFSET 0x1068
#else
#define KDDEBUGGER_DATA_OFFSET 0x2080
#endif

#ifndef _WIN64
#define DUMP_BLOCK_SIZE 0x20000
#else
#define DUMP_BLOCK_SIZE 0x40000
#endif

#define PHYSICAL_ADDRESS_BITS 40

#define ObpDecodeGrantedAccess( Access ) \
    ((Access)& ~ObpAccessProtectCloseBit)

#define ObpDecodeObject( Object ) (PVOID)(((LONG_PTR)Object >> 0x10) & ~(ULONG_PTR)0xF)

#define PTE_PER_PAGE 512
#define PDE_PER_PAGE 512
#define PPE_PER_PAGE 512
#define PXE_PER_PAGE 512

#define PPI_MASK (PPE_PER_PAGE - 1)
#define PXI_MASK (PXE_PER_PAGE - 1)

#define MiGetPxeOffset(va) \
    ((ULONG)(((ULONG_PTR)(va) >> PXI_SHIFT) & PXI_MASK))

#define MiGetPxeAddress(va)   \
    ((PMMPTE)PXE_BASE + MiGetPxeOffset(va))

#define MiGetPpeAddress(va)   \
    ((PMMPTE)(((((ULONG_PTR)(va) & VIRTUAL_ADDRESS_MASK) >> PPI_SHIFT) << PTE_SHIFT) + PPE_BASE))

#define MiGetPdeAddress(va) \
    ((PMMPTE)(((((ULONG_PTR)(va) & VIRTUAL_ADDRESS_MASK) >> PDI_SHIFT) << PTE_SHIFT) + PDE_BASE))

#define MiGetPteAddress(va) \
    ((PMMPTE)(((((ULONG_PTR)(va) & VIRTUAL_ADDRESS_MASK) >> PTI_SHIFT) << PTE_SHIFT) + PTE_BASE))

#define VA_SHIFT (63 - 47)              // address sign extend shift count

#define MiGetVirtualAddressMappedByPte(PTE) \
    ((PVOID)((LONG_PTR)(((LONG_PTR)(PTE) - PTE_BASE) << (PAGE_SHIFT + VA_SHIFT - PTE_SHIFT)) >> VA_SHIFT))

#define MI_IS_PHYSICAL_ADDRESS(Va) \
    ((MiGetPxeAddress(Va)->u.Hard.Valid == 1) && \
     (MiGetPpeAddress(Va)->u.Hard.Valid == 1) && \
     ((MiGetPdeAddress(Va)->u.Long & 0x81) == 0x81) || (MiGetPteAddress(Va)->u.Hard.Valid == 1))

#define ExpIsValidObjectEntry(Entry) \
    ( (Entry != NULL) && (Entry->LowValue != 0) && (Entry->HighValue != EX_ADDITIONAL_INFO_SIGNATURE) )

// Workaround for compiler warning
#define FN_CAST(T, p)   (T)(ULONG_PTR)p
#define FN_CAST_V(p)    (PVOID)(ULONG_PTR)p

// Get SSDT index from function pointer
#define SSDTIndex(pfn)  *(PULONG)((ULONG_PTR)pfn + 0x15)

namespace compatibility {
	enum class windows_version {
        WINVER_7 = 0x0610,
        WINVER_7_SP1 = 0x0611,

        WINVER_8 = 0x0620,
        WINVER_81 = 0x0630,

        WINVER_10 = 0x0A00,
        WINVER_10_RS1 = 0x0A01, // Anniversary update
        WINVER_10_RS2 = 0x0A02, // Creators update
        WINVER_10_RS3 = 0x0A03, // Fall creators update
        WINVER_10_RS4 = 0x0A04, // Spring creators update
        WINVER_10_RS5 = 0x0A05, // October 2018 update
        WINVER_10_19H1 = 0x0A06, // May 2019 update 19H1
        WINVER_10_19H2 = 0x0A07, // November 2019 update 19H2
        WINVER_10_20H1 = 0x0A08, // April 2020 update 20H1 -> 21H1

        WINVER_11_21H2 = 0x0B00 // 2021-09-13 update 21H2 (RTM) and Jun 2021 update Insider Preview 
	};

    struct dynamic_data {
        windows_version version;
        unsigned int protection;
        unsigned int object_table;
        unsigned int debug_port;
        unsigned int thread_cross_flags;
        unsigned int system_thread;
        unsigned int nt_create_thread_ex;
        void* image_callback;
        unsigned int eprocess_flag2;
    };

    NTSTATUS initialize_dynamic_data() noexcept;

    NTSTATUS set_debug_port(PEPROCESS process, unsigned __int64 value);
    NTSTATUS set_system_thread(PETHREAD thread, bool is_system_thread);
    const dynamic_data& get_data();
}