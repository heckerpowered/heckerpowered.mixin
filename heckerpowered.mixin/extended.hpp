#pragma once
#include "memory.hpp"

namespace virtualization::extended
{
	enum MSR
	{
		MsrApicBase = 0x01B,

		MsrFeatureControl = 0x03A,

		MsrSysenterCs = 0x174,
		MsrSysenterEsp = 0x175,
		MsrSysenterEip = 0x176,

		MsrDebugctl = 0x1D9,

		MsrMtrrCap = 0xFE,
		MsrMtrrDefType = 0x2FF,
		MsrMtrrPhysBaseN = 0x200,
		MsrMtrrPhysMaskN = 0x201,
		MsrMtrrFix64k00000 = 0x250,
		MsrMtrrFix16k80000 = 0x258,
		MsrMtrrFix16kA0000 = 0x259,
		MsrMtrrFix4kC0000 = 0x268,
		MsrMtrrFix4kC8000 = 0x269,
		MsrMtrrFix4kD0000 = 0x26A,
		MsrMtrrFix4kD8000 = 0x26B,
		MsrMtrrFix4kE0000 = 0x26C,
		MsrMtrrFix4kE8000 = 0x26D,
		MsrMtrrFix4kF0000 = 0x26E,
		MsrMtrrFix4kF8000 = 0x26F,

		MsrVmxBasic = 0x480,
		MsrVmxPinbasedCtls = 0x481,
		MsrVmxProcBasedCtls = 0x482,
		MsrVmxExitCtls = 0x483,
		MsrVmxEntryCtls = 0x484,
		MsrVmxMisc = 0x485,
		MsrVmxCr0Fixed0 = 0x486,
		MsrVmxCr0Fixed1 = 0x487,
		MsrVmxCr4Fixed0 = 0x488,
		MsrVmxCr4Fixed1 = 0x489,
		MsrVmxVmcsEnum = 0x48A,
		MsrVmxProcBasedCtls2 = 0x48B,
		MsrVmxEptVpidCap = 0x48C,
		MsrVmxTruePinbasedCtls = 0x48D,
		MsrVmxTrueProcBasedCtls = 0x48E,
		MsrVmxTrueExitCtls = 0x48F,
		MsrVmxTrueEntryCtls = 0x490,
		MsrVmxVmfunc = 0x491,

		MsrEfer = 0xC0000080,
		MsrStar = 0xC0000081,
		MsrLstar = 0xC0000082,

		MsrFmask = 0xC0000084,

		MsrFsBase = 0xC0000100,
		MsrGsBase = 0xC0000101,
		MsrKernelGsBase = 0xC0000102,
		MsrTscAux = 0xC0000103,
	};

	typedef union _EptPointer
	{
		ULONG64 all;
		struct
		{
			ULONG64 memory_type : 3;                      //!< [0:2]
			ULONG64 page_walk_length : 3;                 //!< [3:5]
			ULONG64 enable_accessed_and_dirty_flags : 1;  //!< [6]
			ULONG64 reserved1 : 5;                        //!< [7:11]
			ULONG64 pml4_address : 36;                    //!< [12:48-1]
			ULONG64 reserved2 : 16;                       //!< [48:63]
		} fields;
	}Eptp;

	typedef union _EptCommonEntry
	{
		ULONG64 all;
		struct
		{
			ULONG64 read_access : 1;       //!< [0]
			ULONG64 write_access : 1;      //!< [1]
			ULONG64 execute_access : 1;    //!< [2]
			ULONG64 memory_type : 3;       //!< [3:5]
			ULONG64 reserved1 : 6;         //!< [6:11]
			ULONG64 physial_address : 36;  //!< [12:48-1]
			ULONG64 reserved2 : 16;        //!< [48:63]
		} fields;
	}EptCommonEntry;

	static_assert(sizeof(EptCommonEntry) == 8, "Size check");

	extern Eptp extended_page_table_pointer;
	extern char* extended_page;

	constexpr auto memory_size = 32;

	bool initialize() noexcept;

	EptCommonEntry* get_page_table_entry(unsigned __int64 physical_address) noexcept;
}