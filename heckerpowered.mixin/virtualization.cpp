#include "virtualization.hpp"

#ifdef ENABLE_VIRTUALIZATION
namespace virtualization
{
	std::vector<virtualization::virtualizer> virtualizers;

	bool support_virtualization() noexcept
	{
		int cpu_id[4]{};
		__cpuidex(cpu_id, 1, 0);
		return (cpu_id[2] & (1 << 5)) != 0;
	}

	bool enabled_virtualization() noexcept
	{
		return (__readmsr(0x3A) & 1) != 0;
	}

	bool initialize() noexcept
	{
		KeGenericCallDpc([](struct _KDPC*, void*, void* system_argument_1, void* system_argument_2)
		{
			const auto processor_index{ KeGetCurrentProcessorIndex() };
			if (!(support_virtualization() && enabled_virtualization()))
			{
				println("Processor:%d Not supported virtualization.", processor_index);
				return;
			}

			virtualization::virtualizer virtualizer(processor_index);
			if (virtualizer.virtualize()) 
			{ 
				virtualizers.emplace_back(virtualizer);
			}
			else
			{
				println("Failed to launch virtualization on processor id:%d.", processor_index);
			}

			KeSignalCallDpcSynchronize(system_argument_2);
			KeSignalCallDpcDone(system_argument_1);
		}, nullptr);
	}

	unsigned long adjust_control_value(unsigned long msr, unsigned long control) noexcept
	{
		LARGE_INTEGER msr_value{};
		msr_value.QuadPart = __readmsr(msr);
		control &= msr_value.HighPart;
		control |= msr_value.LowPart;
		return control;
	}

	unsigned long vmx_get_segment_access_right(unsigned short segment_selector) noexcept
	{
		VmxRegmentDescriptorAccessRight access_right{};
		if (segment_selector)
		{
			const SegmentSelector selector{ segment_selector };
			ULONG_PTR native_access_right = assembly::load_access_rights_byte(selector.all);
			native_access_right >>= 8;
			access_right.all = (ULONG)(native_access_right);
			access_right.fields.reserved1 = 0;
			access_right.fields.reserved2 = 0;
			access_right.fields.unusable = false;
		}
		else
		{
			access_right.fields.unusable = true;
		}

		return access_right.all;
	}

	SegmentDescriptor* get_segment_descriptor(unsigned __int64 descriptor_table_base, unsigned short segment_selector) noexcept
	{
		const SegmentSelector selector = { segment_selector };
		return reinterpret_cast<SegmentDescriptor*>(descriptor_table_base + selector.fields.index * sizeof(SegmentDescriptor));
	}

	unsigned __int64 get_segment_base_by_descriptor(const SegmentDescriptor* segment_descriptor) noexcept
	{
		const unsigned __int64 base_high{ segment_descriptor->fields.base_high << (6 * 4) };
		const unsigned __int64 base_middle{ segment_descriptor->fields.base_mid << (4 * 4) };
		const unsigned __int64 base_low{ segment_descriptor->fields.base_low };

		unsigned __int64 base = (base_high | base_middle | base_low) & std::numeric_limits<unsigned __int64>::max();

		if (!segment_descriptor->fields.system)
		{
			SegmentDesctiptorX64* desc64 = reinterpret_cast<SegmentDesctiptorX64*>(const_cast<SegmentDescriptor*>(segment_descriptor));
			unsigned __int64 base_upper32 = desc64->base_upper32;
			base |= (base_upper32 << 32);
		}

		return base;
	}

	unsigned __int64 get_segment_base(unsigned __int64 gdt_base, unsigned short segment_selector) noexcept
	{

		SegmentSelector ss = { segment_selector };
		if (!ss.all)
		{
			return 0;
		}

		if (ss.fields.ti)
		{
			SegmentDescriptor* local_segment_descriptor =
				get_segment_descriptor(gdt_base, assembly::read_ldtr());
			ULONG_PTR  ldt_base =
				get_segment_base_by_descriptor(local_segment_descriptor);


			SegmentDescriptor* segment_descriptor =
				get_segment_descriptor(ldt_base, segment_selector);
			return get_segment_base_by_descriptor(segment_descriptor);
		}
		else
		{
			SegmentDescriptor* segment_descriptor =
				get_segment_descriptor(gdt_base, segment_selector);
			return get_segment_base_by_descriptor(segment_descriptor);
		}
	}

	virtualizer::virtualizer(unsigned long index) noexcept : index(index)
	{
		vmx_region = reinterpret_cast<unsigned __int64>(memory::allocate_contiguous(PAGE_SIZE));
		vmcs_region = reinterpret_cast<unsigned __int64>(memory::allocate_contiguous(PAGE_SIZE));
		msr_bitmap = reinterpret_cast<unsigned __int64>(memory::allocate_contiguous(PAGE_SIZE));
		vmm_stack = reinterpret_cast<char*>(memory::allocate_contiguous(VMM_STACK_SIZE));
		println("Constructing virtualizer in processor id:%d", index);
	}

	virtualizer::~virtualizer() noexcept
	{
		Cr4 cr4{};
		cr4.all = __readcr4();
		if (cr4.fields.vmxe)
		{
			cr4.fields.vmxe = 0;
			__writecr4(cr4.all);
		}

		memory::free(reinterpret_cast<void*>(vmx_region));
		memory::free(reinterpret_cast<void*>(vmcs_region));
		memory::free(reinterpret_cast<void*>(msr_bitmap));
		memory::free(vmm_stack);

		Ia32FeatureControlMsr msr{};
		msr.all = __readmsr(MSR::MsrFeatureControl);
		if (msr.fields.lock)
		{
			msr.fields.lock = false;
			msr.fields.enable_vmxon = false;
			__writemsr(MsrFeatureControl, msr.all);
			msr.all = __readmsr(MsrFeatureControl);
		}
	}

	bool virtualizer::vmx_on() noexcept
	{
		#pragma warning(push)
		#pragma warning(disable:4244)
		* reinterpret_cast<ULONG*>(vmx_region) = __readmsr(MSR::MsrVmxBasic);
		*reinterpret_cast<ULONG*>(vmx_region) = __readmsr(MSR::MsrVmxBasic);
		#pragma warning(pop)

		Cr4 cr4{};
		cr4.all = __readcr4();
		cr4.fields.vmxe = true;
		__writecr4(cr4.all);

		Ia32FeatureControlMsr msr{};
		msr.all = __readmsr(MSR::MsrFeatureControl);
		if (!msr.fields.lock)
		{
			msr.fields.lock = true;
			msr.fields.enable_vmxon = true;
			__writemsr(MSR::MsrFeatureControl, msr.all);
			msr.all = __readmsr(MSR::MsrFeatureControl);
		}

		auto physical_address{ static_cast<unsigned __int64>(MmGetPhysicalAddress(reinterpret_cast<void*>(vmx_region)).QuadPart) };
		__vmx_on(&physical_address);

		FlagRegister flags{};
		*reinterpret_cast<unsigned __int64*>(&flags) = __readeflags();
		if (flags.fields.cf != 0)
		{
			println("Unable to execute vmx_on on processor id:%d", index);
			return false;
		}

		physical_address = MmGetPhysicalAddress(reinterpret_cast<void*>(vmcs_region)).QuadPart;
		__vmx_vmclear(&physical_address);
		__vmx_vmptrld(&physical_address);
		return true;
	}

	bool virtualizer::initialize_vmcs(void* guest_stack, void* guest_resume_rip) noexcept
	{
		Ia32VmxBasicMsr vmx_basic_msr{ __readmsr(MSR::MsrVmxBasic) };

		VmxPinBasedControls vmx_pin_base_controls_requested{};
		VmxPinBasedControls vmx_pin_based_controls {adjust_control_value((vmx_basic_msr.fields.vmx_capability_hint) ? MSR::MsrVmxTruePinbasedCtls 
			: MSR::MsrVmxPinbasedCtls, vmx_pin_base_controls_requested.all) };
		__vmx_vmwrite(VmcsField::PinBasedVmExecutionControls, vmx_pin_based_controls.all);

		VmxProcessorBasedControls vmx_processor_base_controls_requested{};
		vmx_processor_base_controls_requested.fields.use_msr_bitmaps = true;
		vmx_processor_base_controls_requested.fields.activate_secondary_control = true;
		VmxProcessorBasedControls vm_procctl {adjust_control_value((vmx_basic_msr.fields.vmx_capability_hint) ? MSR::MsrVmxTrueProcBasedCtls
			: MSR::MsrVmxProcBasedCtls, vmx_processor_base_controls_requested.all) };
		__vmx_vmwrite(VmcsField::PrimaryProcessorBasedVmExecutionControls, vm_procctl.all);

		VmxSecondaryProcessorBasedControls vmx_secondary_processor_based_controls_requested{};

		vmx_secondary_processor_based_controls_requested.fields.enable_rdtscp = true;
		vmx_secondary_processor_based_controls_requested.fields.enable_invpcid = true;
		vmx_secondary_processor_based_controls_requested.fields.enable_xsaves_xstors = true;

		vmx_secondary_processor_based_controls_requested.fields.enable_ept = true;
		vmx_secondary_processor_based_controls_requested.fields.enable_vpid = true;

		VmxSecondaryProcessorBasedControls vmx_secondary_procesor_based_controls = { adjust_control_value(
			MSR::MsrVmxProcBasedCtls2, vmx_secondary_processor_based_controls_requested.all) };

		__vmx_vmwrite(VmcsField::SecondaryProcessorBasedVmExecutionControls, vmx_secondary_procesor_based_controls.all);

		VmxVmEntryControls vmx_vm_entry_controls_requested{};
		vmx_vm_entry_controls_requested.fields.ia32e_mode_guest = true;
		VmxVmEntryControls vmx_vm_entry_controls = { adjust_control_value(vmx_basic_msr.fields.vmx_capability_hint ? MSR::MsrVmxTrueEntryCtls 
			: MSR::MsrVmxEntryCtls, vmx_vm_entry_controls_requested.all) };

		__vmx_vmwrite(VmcsField::VmEntryControls, vmx_vm_entry_controls.all);

		VmxVmExitControls vmx_vm_exit_controls_requested{};
		vmx_vm_exit_controls_requested.fields.host_address_space_size = true;
		VmxVmExitControls vmx_vm_exit_controls = { adjust_control_value(vmx_basic_msr.fields.vmx_capability_hint ? 
			MSR::MsrVmxTrueExitCtls : MSR::MsrVmxExitCtls, vmx_vm_exit_controls_requested.all) };
		__vmx_vmwrite(VmExitControls, vmx_vm_exit_controls.all);

		Cr0 cr0_mask{};
		Cr0 cr0_shadow{ __readcr0() };

		Cr4 cr4_mask{};
		Cr4 cr4_shadow{ __readcr4() };

		__vmx_vmwrite(VmcsField::Cr0GuestHostMask, cr0_mask.all);
		__vmx_vmwrite(VmcsField::Cr4GuestHostMask, cr4_mask.all);
		__vmx_vmwrite(VmcsField::Cr0ReadShadow, 0);
		__vmx_vmwrite(VmcsField::Cr4ReadShadow, 0);


		unsigned __int64 msr_bitmap_physical_address(MmGetPhysicalAddress(reinterpret_cast<void*>(VmcsField::MsrBitmap)).QuadPart);
		__vmx_vmwrite(VmcsField::MsrBitmap, msr_bitmap_physical_address);

		unsigned __int64 exception_bitmap{};
		__vmx_vmwrite(VmcsField::ExceptionBitmap, exception_bitmap);

		auto processor{ KeGetCurrentProcessorNumberEx(nullptr) };

		__vmx_vmwrite(VmcsField::EptPointer, extended::extended_page_table_pointer.all);
		__vmx_vmwrite(VmcsField::VirtualProcessorId, static_cast<std::size_t>(processor) + 1);

		Gdtr gdtr{};
		_sgdt(&gdtr);

		Idtr idtr{};
		__sidt(&idtr);

		__vmx_vmwrite(VmcsField::GuestEsSelector, assembly::read_es());
		__vmx_vmwrite(VmcsField::GuestCsSelector, assembly::read_cs());
		__vmx_vmwrite(VmcsField::GuestSsSelector, assembly::read_ss());
		__vmx_vmwrite(VmcsField::GuestDsSelector, assembly::read_ds());
		__vmx_vmwrite(VmcsField::GuestFsSelector, assembly::read_fs());
		__vmx_vmwrite(VmcsField::GuestGsSelector, assembly::read_gs());
		__vmx_vmwrite(VmcsField::GuestLDTRSelector, assembly::read_ldtr());
		__vmx_vmwrite(VmcsField::GuestTRSelector, assembly::read_tr());

		__vmx_vmwrite(VmcsField::GuestVmcsLinkPointer, MAXULONG64);
		__vmx_vmwrite(VmcsField::GuestIa32DebugCtl, __readmsr(MSR::MsrDebugctl));

		__vmx_vmwrite(VmcsField::GuestEsLimit, __segmentlimit(assembly::read_es()));
		__vmx_vmwrite(VmcsField::GuestCsLimit, __segmentlimit(assembly::read_cs()));
		__vmx_vmwrite(VmcsField::GuestSsLimit, __segmentlimit(assembly::read_ss()));
		__vmx_vmwrite(VmcsField::GuestDsLimit, __segmentlimit(assembly::read_ds()));
		__vmx_vmwrite(VmcsField::GuestFsLimit, __segmentlimit(assembly::read_fs()));
		__vmx_vmwrite(VmcsField::GuestGsLimit, __segmentlimit(assembly::read_gs()));
		__vmx_vmwrite(VmcsField::GuestLDTRLimit, __segmentlimit(assembly::read_ldtr()));
		__vmx_vmwrite(VmcsField::GuestTRLimit, __segmentlimit(assembly::read_tr()));
		__vmx_vmwrite(VmcsField::GuestGDTRLimit, gdtr.limit);
		__vmx_vmwrite(VmcsField::GuestIDTRLimit, idtr.limit);

		__vmx_vmwrite(VmcsField::GuestEsAccessRight, vmx_get_segment_access_right(assembly::read_es()));
		__vmx_vmwrite(VmcsField::GuestCsAccessRight, vmx_get_segment_access_right(assembly::read_cs()));
		__vmx_vmwrite(VmcsField::GuestSsAccessRight, vmx_get_segment_access_right(assembly::read_ss()));
		__vmx_vmwrite(VmcsField::GuestDsAccessRight, vmx_get_segment_access_right(assembly::read_ds()));
		__vmx_vmwrite(VmcsField::GuestFsAccessRight, vmx_get_segment_access_right(assembly::read_fs()));
		__vmx_vmwrite(VmcsField::GuestGsAccessRight, vmx_get_segment_access_right(assembly::read_gs()));
		__vmx_vmwrite(VmcsField::GuestLDTRAccessRight, vmx_get_segment_access_right(assembly::read_ldtr()));
		__vmx_vmwrite(VmcsField::GuestTRAccessRight, vmx_get_segment_access_right(assembly::read_tr()));
		__vmx_vmwrite(VmcsField::GuestIa32SYSENTERCS, __readmsr(MSR::MsrSysenterCs));

		__vmx_vmwrite(VmcsField::GuestCr0, __readcr0());
		__vmx_vmwrite(VmcsField::GuestCr3, __readcr3());
		__vmx_vmwrite(VmcsField::GuestCr4, __readcr4());

		__vmx_vmwrite(VmcsField::GuestEsBase, 0);
		__vmx_vmwrite(VmcsField::GuestCsBase, 0);
		__vmx_vmwrite(VmcsField::GuestSsBase, 0);
		__vmx_vmwrite(VmcsField::GuestDsBase, 0);
		#pragma warning(push)
		#pragma warning(disable:4245)
		__vmx_vmwrite(VmcsField::GuestFsBase, __readmsr(MSR::MsrFsBase));
		__vmx_vmwrite(VmcsField::GuestGsBase, __readmsr(MSR::MsrGsBase));

		__vmx_vmwrite(VmcsField::GuestLDTRBase, get_segment_base(gdtr.base, assembly::read_ldtr()));
		__vmx_vmwrite(VmcsField::GuestTRBase, get_segment_base(gdtr.base, assembly::read_tr()));
		__vmx_vmwrite(VmcsField::GuestGDTRBase, gdtr.base);
		__vmx_vmwrite(VmcsField::GuestIDTRBase, idtr.base);
		__vmx_vmwrite(VmcsField::GuestDr7, __readdr(7));
		__vmx_vmwrite(VmcsField::GuestRsp, reinterpret_cast<std::size_t>(guest_stack));
		__vmx_vmwrite(VmcsField::GuestRip, reinterpret_cast<std::size_t>(guest_resume_rip));
		__vmx_vmwrite(VmcsField::GuestRflags, __readeflags());
		__vmx_vmwrite(VmcsField::GuestIa32SYSENTERESP, __readmsr(MSR::MsrSysenterEsp));
		__vmx_vmwrite(VmcsField::GuestIa32SYSENTEREIP, __readmsr(MSR::MsrSysenterEip));

		__vmx_vmwrite(VmcsField::HostEsSelector, assembly::read_es() & 0xf8);
		__vmx_vmwrite(VmcsField::HostCsSelector, assembly::read_cs() & 0xf8);
		__vmx_vmwrite(VmcsField::HostSsSelector, assembly::read_ss() & 0xf8);
		__vmx_vmwrite(VmcsField::HostDsSelector, assembly::read_ds() & 0xf8);
		__vmx_vmwrite(VmcsField::HostFsSelector, assembly::read_fs() & 0xf8);
		__vmx_vmwrite(VmcsField::HostGsSelector, assembly::read_gs() & 0xf8);
		__vmx_vmwrite(VmcsField::HostTrSelector, assembly::read_tr() & 0xf8);
		__vmx_vmwrite(VmcsField::HostIa32SYSENTERCS, __readmsr(MSR::MsrSysenterCs));
		__vmx_vmwrite(VmcsField::HostCr0, __readcr0());
		__vmx_vmwrite(VmcsField::HostCr3, __readcr3());
		__vmx_vmwrite(VmcsField::HostCr4, __readcr4());
		__vmx_vmwrite(VmcsField::HostFsBase, __readmsr(MSR::MsrFsBase));
		__vmx_vmwrite(VmcsField::HostGsBase, __readmsr(MSR::MsrGsBase));
		#pragma warning(pop)
		__vmx_vmwrite(VmcsField::HostTrBase, get_segment_base(gdtr.base, assembly::read_tr()));
		__vmx_vmwrite(VmcsField::HostGDTRBase, gdtr.base);
		__vmx_vmwrite(VmcsField::HostIDTRBase, idtr.base);
		__vmx_vmwrite(VmcsField::HostIa32SYSENTERESP, __readmsr(MSR::MsrSysenterEsp));
		__vmx_vmwrite(VmcsField::HostIa32SYSENTEREIP, __readmsr(MSR::MsrSysenterEip));

		__vmx_vmwrite(VmcsField::HostRsp, reinterpret_cast<std::size_t>(vmm_stack + VMM_STACK_SIZE - 0x1000));
		__vmx_vmwrite(VmcsField::HostRip, reinterpret_cast<std::size_t>(assembly::vmm_entry_point));

		__vmx_vmlaunch();

		unsigned __int64 error_code{};
		__vmx_vmread(VmcsField::VmVMInstructionError, &error_code);
		println("VmLaunch error! code: %d", error_code);

		return false;
	}

	bool virtualizer::virtualize() noexcept
	{
		enabled = vmx_on();
		if (!enabled)
		{
			println("Failed to virtualize on processor id:%d", index);
			return false;
		}

		union function_address
		{
			void* address;
			bool(virtualizer::* fun)(void*, void*);
		}address{};

		address.fun = &virtualizer::initialize_vmcs;
		enabled = assembly::vmx_launch(address.address, this);
	}

	void EptViolationHandle()
	{
		//获取触发EptViolation的地址
		ULONG_PTR ExitPhyAddr = 0;
		__vmx_vmread(VmExitGuestPhysicalAddress, &ExitPhyAddr);

		//通过触发EptViolation的地址，查找是不是跟我们HOOK有关
		PEptHookInfo hookInfo = hook::virtual_hook::get_hook(ExitPhyAddr);

		if (hookInfo)
		{
			EptCommonEntry* pte = extended::get_page_table_entry(ExitPhyAddr);

			if (pte->fields.execute_access)
			{
				pte->fields.execute_access = 0;
				pte->fields.read_access = 1;
				pte->fields.write_access = 1;
				pte->fields.physial_address = hookInfo->RealPagePhyAddr >> 12;
			}
			else
			{
				pte->fields.execute_access = 1;
				pte->fields.read_access = 0;
				pte->fields.write_access = 0;
				pte->fields.physial_address = hookInfo->FakePagePhyAddr >> 12;
			}
		}
		else
		{
			DbgBreakPoint();
		}
	}

	void VmmAdjustGuestRip()
	{
		ULONG instLen{};
		ULONG_PTR rip{};
		__vmx_vmread(VmcsField::GuestRip, &rip);
		__vmx_vmread(VmcsField::VmExitInstructionLength, (SIZE_T*)&instLen);
		__vmx_vmwrite(VmcsField::GuestRip, reinterpret_cast<std::size_t>(rip + instLen));
	}

	//退出VT，这里我是CV了其他项目的
	void VmxPrepareOff(GpRegisters* pGuestRegisters)
	{
		/*
		当发生VM退出时，处理器将IDT和GDT的Limit设置为ffff。
		这里把它改回正确的值
		*/
		ULONG_PTR gdt_limit = 0;
		__vmx_vmread(GuestGDTRLimit, &gdt_limit);

		ULONG_PTR gdt_base = 0;
		__vmx_vmread(GuestGDTRBase, &gdt_base);
		ULONG_PTR idt_limit = 0;
		__vmx_vmread(GuestIDTRLimit, &idt_limit);
		ULONG_PTR idt_base = 0;
		__vmx_vmread(GuestIDTRBase, &idt_base);

		Gdtr gdtr = { (USHORT)gdt_limit, gdt_base };
		Idtr idtr = { (USHORT)(idt_limit), idt_base };
		assembly::write_gdt(&gdtr);
		__lidt(&idtr);


		//跳过VmCall指令
		ULONG_PTR exit_instruction_length = 0;
		__vmx_vmread(VmExitInstructionLength, &exit_instruction_length);
		ULONG_PTR rip = 0;
		__vmx_vmread(GuestRip, &rip);
		ULONG_PTR return_address = rip + exit_instruction_length;

		// Since the flag register is overwritten after VMXOFF, we should manually
		// indicates that VMCALL was successful by clearing those flags.
		// See: CONVENTIONS
		FlagRegister rflags = { 0 };
		__vmx_vmread(GuestRflags, (SIZE_T*)&rflags);

		rflags.fields.cf = FALSE;
		rflags.fields.pf = FALSE;
		rflags.fields.af = FALSE;
		rflags.fields.zf = FALSE;
		rflags.fields.sf = FALSE;
		rflags.fields.of = FALSE;
		rflags.fields.cf = FALSE;
		rflags.fields.zf = FALSE;

		// Set registers used after VMXOFF to recover the context. Volatile
		// registers must be used because those changes are reflected to the
		// guest's context after VMXOFF.
		pGuestRegisters->cx = return_address;
		__vmx_vmread(GuestRsp, &pGuestRegisters->dx);
		pGuestRegisters->ax = rflags.all;
	}

	//处理MSR的读写，不用理，CV即可
	VOID ReadWriteMsrHandle(GpRegisters* pGuestRegisters, BOOLEAN isRead)
	{
		MSR msr = (MSR)__readmsr(pGuestRegisters->cx);

		BOOLEAN transfer_to_vmcs = false;
		VmcsField vmcs_field = {};
		switch (msr)
		{
			case MSR::MsrSysenterCs:
				vmcs_field = VmcsField::GuestIa32SYSENTERCS;
				transfer_to_vmcs = true;
				break;
			case MSR::MsrSysenterEsp:
				vmcs_field = VmcsField::GuestIa32SYSENTERESP;
				transfer_to_vmcs = true;
				break;
			case MSR::MsrSysenterEip:
				vmcs_field = VmcsField::GuestIa32SYSENTEREIP;
				transfer_to_vmcs = true;
				break;
			case MSR::MsrDebugctl:
				vmcs_field = VmcsField::GuestIa32DebugCtl;
				transfer_to_vmcs = true;
				break;
			case MSR::MsrGsBase:
				vmcs_field = VmcsField::GuestGsBase;
				transfer_to_vmcs = true;
				break;
			case MSR::MsrFsBase:
				vmcs_field = VmcsField::GuestFsBase;
				transfer_to_vmcs = true;
				break;
			default:
				break;
		}

		LARGE_INTEGER msr_value = {};
		if (isRead)
		{
			if (transfer_to_vmcs)
			{
				__vmx_vmread(vmcs_field, (SIZE_T*)&msr_value.QuadPart);
			}
			else
			{
				__vmx_vmread(msr, (SIZE_T*)&msr_value.QuadPart);
			}

			pGuestRegisters->ax = msr_value.LowPart;
			pGuestRegisters->dx = msr_value.HighPart;
		}
		else
		{
			msr_value.LowPart = (ULONG)pGuestRegisters->ax;
			msr_value.HighPart = (ULONG)pGuestRegisters->dx;
			if (transfer_to_vmcs)
			{
				__vmx_vmwrite(vmcs_field, (ULONG_PTR)msr_value.QuadPart);
			}
			else
			{
				__vmx_vmwrite(msr, (ULONG_PTR)msr_value.QuadPart);
			}
		}
	}

	BOOLEAN VmCallHandle(GpRegisters* pGuestRegisters)
	{
		//x64下都是fastcall调用约定
		//VmCall的功能号
		ULONG_PTR num = pGuestRegisters->cx;
		//附加的参数
		ULONG_PTR param = pGuestRegisters->dx;

		BOOLEAN ContinueVmx = TRUE;

		EptCommonEntry* pte = 0;
		PEptHookInfo hookInfo = 0;

		switch (num)
		{
			case CallExitVT:
				ContinueVmx = FALSE;
				VmxPrepareOff(pGuestRegisters);
				break;
			case CallEptHook:
				//HOOK的时候，把原函数所在页改成复制出来的页面，并且只能执行
				hookInfo = (PEptHookInfo)param;
				pte = GetPteByPhyAddr(hookInfo->RealPagePhyAddr);
				if (pte)
				{
					pte->fields.physial_address = hookInfo->FakePagePhyAddr >> 12;
					pte->fields.execute_access = 1;
					pte->fields.read_access = 0;
					pte->fields.write_access = 0;
				}
				break;
			case CallEptUnHook:
				//HOOK的时候，把原函数所在页改回去，并且赋予全部权限
				hookInfo = (PEptHookInfo)param;
				pte = GetPteByPhyAddr(hookInfo->RealPagePhyAddr);
				if (pte)
				{
					pte->fields.physial_address = hookInfo->RealPagePhyAddr >> 12;
					pte->fields.execute_access = 1;
					pte->fields.read_access = 1;
					pte->fields.write_access = 1;
				}
				break;
			default:
				Log("未知的VmCall");
				break;
		}

		return ContinueVmx;
	}

	extern "C" bool vm_exit_handler(GpRegisters * guest_registers) noexcept
	{
		KIRQL irql = KeGetCurrentIrql();
		if (irql < DISPATCH_LEVEL)
		{
			KeRaiseIrqlToDpcLevel();
		}

		ULONG CurrentProcessorIndex = KeGetCurrentProcessorNumberEx(NULL);
		VmExitInformation ExitReason = { 0 };
		FlagRegister guestRflag = { 0 };
		BOOLEAN ContinueVmx = TRUE;
		ULONG_PTR Rip = 0;

		__vmx_vmread(GuestRip, &Rip);
		__vmx_vmread(VmExitReason, (SIZE_T*)(&ExitReason));


		switch (ExitReason.fields.reason)
		{
			case ExitTripleFault:
				__debugbreak();
				break;
			case ExitEptMisconfig:
				__debugbreak();
				break;
			case ExitEptViolation:
				EptViolationHandle();
				break;
			case ExitCrAccess:
				break;
				//msr读写必须处理
			case ExitMsrRead:
			{
				Log("ExitMsrRead %p", Rip);
				ReadWriteMsrHandle(pGuestRegisters, TRUE);
				VmmAdjustGuestRip();
				break;
			}
			case ExitMsrWrite:
			{
				Log("ExitMsrWrite");
				ReadWriteMsrHandle(pGuestRegisters, FALSE);
				VmmAdjustGuestRip();
				break;
			}
			case ExitCpuid:
			{
				//Log("ExitCpuid");
				//访问很频繁
				int leaf = (int)pGuestRegisters->ax;
				int sub_leaf = (int)pGuestRegisters->cx;
				int result[4] = { 0 };
				__cpuidex((int*)&result, leaf, sub_leaf);

				//if (leaf ==1)
				//{
				//	//((CpuFeaturesEcx*)&result[2])->fields.
				//}
				pGuestRegisters->ax = result[0];
				pGuestRegisters->bx = result[1];
				pGuestRegisters->cx = result[2];
				pGuestRegisters->dx = result[3];
				VmmAdjustGuestRip();
				break;
			}
			case ExitIoInstruction:
			{
				Log("ExitIoInstruction");
				VmmAdjustGuestRip();
				break;
			}
			case ExitVmcall:
			{
				ContinueVmx = VmCallHandle(pGuestRegisters);
				//如果不是退出VT，跳过VmCall指令继续执行
				if (ContinueVmx) VmmAdjustGuestRip();
				break;
			}
			case ExitExceptionOrNmi:
			{
				Log("ExitExceptionOrNmi");
				VmExitInterruptionInformationField exception = { 0 };
				__vmx_vmread(VmExitInterruptionInformation, (SIZE_T*)&exception);

				if (exception.fields.interruption_type == kHardwareException)
				{
					//VmmpInjectInterruption(exception.fields.interruption_type,)
					exception.fields.valid = TRUE;
					__vmx_vmwrite(VmEntryInterruptionInformation, exception.all);
				}
				else if (exception.fields.interruption_type == kSoftwareException)
				{
					__vmx_vmwrite(VmEntryInterruptionInformation, exception.all);
					int exit_inst_length = 0;
					__vmx_vmread(VmExitInstructionLength, (SIZE_T*)&exit_inst_length);
					__vmx_vmwrite(VmEntryInstructionLength, exit_inst_length);
				}
				break;
			}
			case ExitMonitorTrapFlag:
			{
				Log("ExitMonitorTrapFlag");

				break;
			}
			case ExitHlt:
			{
				Log("ExitHlt");
				break;
			}
			case ExitVmclear:
			case ExitVmptrld:
			case ExitVmptrst:
			case ExitVmread:
			case ExitVmwrite:
			case ExitVmresume:
			case ExitVmoff:
			case ExitVmon:
			case ExitVmlaunch:
			case ExitVmfunc:
			case ExitInvept:
			case ExitInvvpid:
			{
				Log("vm inst %d", ExitReason.fields.reason);
				__vmx_vmread(GuestRflags, (SIZE_T*)&guestRflag);
				guestRflag.fields.cf = 1;
				__vmx_vmwrite(GuestRflags, guestRflag.all);
				VmmAdjustGuestRip();
				break;
			}
			case ExitInvd:
			{
				Log("ExitInvd");
				AsmInvd();
				VmmAdjustGuestRip();
				break;
			}
			case ExitInvlpg:
			{
				Log("ExitInvlpg");
				ExitQualification eq = { 0 };
				__vmx_vmread(VmExitQualification, (SIZE_T*)&eq);
				InvVpidDescriptor desc = { 0 };
				desc.vpid = CurrentProcessorIndex + 1;
				desc.linear_address = eq.all;
				AsmInvvpid(kIndividualAddressInvalidation, (SIZE_T*)&desc);
				VmmAdjustGuestRip();
				break;
			}
			case ExitRdtsc:
			{
				Log("ExitRdtsc");

				ULARGE_INTEGER tsc = { 0 };
				tsc.QuadPart = __rdtsc();
				pGuestRegisters->dx = tsc.HighPart;
				pGuestRegisters->ax = tsc.LowPart;
				VmmAdjustGuestRip();
				break;
			}
			case ExitRdtscp:
			{
				Log("ExitRdtscp");

				unsigned int tsc_aux = 0;
				ULARGE_INTEGER tsc = { 0 };
				tsc.QuadPart = __rdtscp(&tsc_aux);
				pGuestRegisters->dx = tsc.HighPart;
				pGuestRegisters->ax = tsc.LowPart;
				pGuestRegisters->cx = tsc_aux;
				VmmAdjustGuestRip();
				break;
			}
			case ExitXsetbv:
			{
				Log("ExitXsetbv");

				ULARGE_INTEGER value = { 0 };
				value.LowPart = pGuestRegisters->ax;
				value.HighPart = pGuestRegisters->dx;
				_xsetbv(pGuestRegisters->cx, value.QuadPart);

				VmmAdjustGuestRip();
				break;
			}
			default:
				println("Unexpected Exit %d", ExitReason.fields.reason);
				DbgBreakPoint();
				break;
		}

		if (irql < DISPATCH_LEVEL)
		{
			KeLowerIrql(irql);
		}

		return ContinueVmx;
	}
}
#endif