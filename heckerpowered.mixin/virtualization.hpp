#pragma once
#ifdef ENABLE_VIRTUALIZATION
#include <intrin.h>
#include <ntifs.h>
#include "util.hpp"
#include "ia32.hpp"
#include "extended.hpp"
#include "virtualization_assembly.hpp"
#include "virtual_hook.hpp"

namespace virtualization
{
	#define VMM_STACK_SIZE 10*PAGE_SIZE

	EXTERN_C
		NTKERNELAPI
		_IRQL_requires_max_(APC_LEVEL)
		_IRQL_requires_min_(PASSIVE_LEVEL)
		_IRQL_requires_same_
		VOID
		KeGenericCallDpc(
			_In_ PKDEFERRED_ROUTINE Routine,
			_In_opt_ PVOID Context
		);

	EXTERN_C
		NTKERNELAPI
		_IRQL_requires_(DISPATCH_LEVEL)
		_IRQL_requires_same_
		VOID
		KeSignalCallDpcDone(
			_In_ PVOID SystemArgument1
		);

	EXTERN_C
		NTKERNELAPI
		_IRQL_requires_(DISPATCH_LEVEL)
		_IRQL_requires_same_
		LOGICAL
		KeSignalCallDpcSynchronize(
			_In_ PVOID SystemArgument2
		);

	typedef struct _EptHookInfo
	{
		ULONG_PTR RealPagePhyAddr;

		ULONG_PTR FakePagePhyAddr;
		ULONG_PTR FakePageVaAddr;

		ULONG_PTR OriginalFunAddr;
		ULONG_PTR OriginalFunHeadCode;

		LIST_ENTRY list;
	} EptHookInfo, * PEptHookInfo;

	typedef struct _SYSTEM_SERVICE_TABLE
	{
		PLONG  		ServiceTableBase;
		PVOID  		ServiceCounterTableBase;
		ULONGLONG  	NumberOfServices;
		PVOID  		ParamTableBase;
	} SYSTEM_SERVICE_TABLE, * PSYSTEM_SERVICE_TABLE;

	unsigned long adjust_control_value(unsigned long msr, unsigned long control) noexcept;
	unsigned long vmx_get_segment_access_right(unsigned short segment_selector) noexcept;
	SegmentDescriptor* get_segment_descriptor(unsigned __int64 descriptor_table_base, unsigned short segment_selector) noexcept;
	unsigned __int64 get_segment_base_by_descriptor(const SegmentDescriptor* segment_descriptor) noexcept;
	unsigned __int64 get_segment_base(unsigned __int64 gdt_base, unsigned short segment_selector) noexcept;
	bool support_virtualization() noexcept;
	bool enabled_virtualization() noexcept;
	bool initialize() noexcept;
	extern "C" bool vm_exit_handler(GpRegisters * guest_registers) noexcept;

	class virtualizer
	{
	public:
		unsigned long index;
		bool enabled;

		unsigned __int64 vmx_region;
		unsigned __int64 vmcs_region;
		unsigned __int64 msr_bitmap;
		char* vmm_stack;

		virtualizer(unsigned long index) noexcept;
		~virtualizer() noexcept;
		bool vmx_on() noexcept;
		bool initialize_vmcs(void* guestStack, void* guestResumeRip) noexcept;
		bool virtualize() noexcept;
	};
}
#endif