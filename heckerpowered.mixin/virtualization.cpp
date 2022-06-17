#include "pch.hpp"

namespace virtualization
{
	VIRTUAL_MACHINE_STATE* guest_state;
	EPT_STATE* ept_state;
	bool execute_only_support;
	std::uint64_t* msr_bitmap_invalid_msrs;

	/**
	 * @brief Vmx-root lock for changing EPT PML1 Entry and Invalidating TLB
	 *
	 */
	KSPIN_LOCK Pml1ModificationAndInvalidationLock;

	bool check_hypervisor_support() noexcept
	{
		CPUID data{};

		//
		// Calling __cpuid with 1 as the InfoType argument gets processor and feature bits. 
		//
		__cpuid(reinterpret_cast<int*>(&data), 1);

		//
		// Determine whether current processor supports VMX operation.
		// If cpuid.1:ECX.VMX[bit 5] = 1, then VMX operation is supported.
		//
		if (!_bittest(reinterpret_cast<const long*>(&data.ecx), 5))
		{

			//
			// VMX operation is not supported.
			//
			return false;
		}

		//
		// VMXON is also controlled by the IA32_FEATURE_CONTROL_MSR (MSR address 3AH).
		// This MSR is cleared to zero when a logical processor is reset.
		//
		IA32_FEATURE_CONTROL_REGISTER feature_control_msr{ .Flags = __readmsr(IA32_FEATURE_CONTROL) };

		//
		// Bit 0 is the lock bit, if lock bit is clear, VMXON causes a general-protection exception.
		// However, it is not necessary to check lock bit.
		// The lock bit is not set to 0 on most computers, if user enabled VT-X
		// from the BIOS the VMXON will be already set so checking lock.
		//

		//
		// Bit 2 enables VMXON outside SMX opreation.
		//
		if (!feature_control_msr.EnableVmxOutsideSmx)
		{

			//
			// Execution of VMXON outside smx operation causes a general-protection exception.
			//
			return false;
		}

		return true;
	}

	bool ept_check_features() noexcept
	{
		IA32_VMX_EPT_VPID_CAP_REGISTER vpid_register{.Flags = __readmsr(IA32_VMX_EPT_VPID_CAP) };
		IA32_MTRR_DEF_TYPE_REGISTER mtrr_def_type{ .Flags = __readmsr(IA32_MTRR_DEF_TYPE) };

		if (!vpid_register.PageWalkLength4 || !vpid_register.MemoryTypeWriteBack || !vpid_register.Pde2MbPages)
		{
			return false;
		}

		if (!vpid_register.AdvancedVmexitEptViolationsInformation)
		{
			io::println("The processor doesn't report advanced VM-exit information for EPT violations");
		}

		if (!vpid_register.ExecuteOnlyPages)
		{
			execute_only_support = false;
			io::println("The processor doesn't support execute-only pages, execute hooks won't work as they're on this feature in our design.");
		}
		else
		{
			execute_only_support = true;
		}

		if (!mtrr_def_type.MtrrEnable)
		{
			io::println("MTRR dynamic ranges are not supported");
			return false;
		}

		return true;
	}

	bool ept_build_mtrr_map() noexcept
	{
		IA32_MTRR_CAPABILITIES_REGISTER mtrr_cap{ .Flags = __readmsr(IA32_MTRR_CAPABILITIES) };
		for (std::uint64_t current_register{}; current_register < mtrr_cap.VariableRangeCount; current_register++)
		{
			//
			// For each dynamic register pair
			//
			IA32_MTRR_PHYSBASE_REGISTER current_physical_base{ .Flags = __readmsr(static_cast<unsigned long>(IA32_MTRR_PHYSBASE0 + current_register * 2)) };
			IA32_MTRR_PHYSMASK_REGISTER current_physical_mask{ .Flags = __readmsr(static_cast<unsigned long>(IA32_MTRR_PHYSMASK0 + current_register * 2)) };

			//
			// Determine whether the range is enabled.
			//
			if (current_physical_mask.Valid)
			{
				//
				// We only need to read these once because the ISA dictates that MTRRs are
				// to be synchronized between all processors during BIOS initialization.
				//
				PMTRR_RANGE_DESCRIPTOR descriptor{ &ept_state->MemoryRanges[ept_state->NumberOfEnabledMemoryRanges++] };

				//
				// Caculate the base address in bytes.
				//
				descriptor->PhysicalBaseAddress = current_physical_base.PageFrameNumber * PAGE_SIZE;

				std::uint32_t number_of_bits_in_mask{};

				//
				// Caculate the total size of the range
				// The lowest bit of the mask that is set to 1 specifies the size of the range
				//
				_BitScanForward64(reinterpret_cast<unsigned long*>(number_of_bits_in_mask), current_physical_mask.PageFrameNumber * PAGE_SIZE);

				//
				// Size of the range in bytes + Base Address
				//
				descriptor->PhysicalEndAddress = descriptor->PhysicalBaseAddress + ((1ULL << number_of_bits_in_mask) - 1ULL);

				//
				// Memory Type (cacheability attributes)
				//
				descriptor->MemoryType = current_physical_base.Type;

				if (descriptor->MemoryType == MEMORY_TYPE_WRITE_BACK)
				{
					//
					// This is already our default, so no need to store this range.
					// Simply 'free' the range we just wrote.
					//
					ept_state->NumberOfEnabledMemoryRanges--;
				}
			}
		}

		return true;
	}

	void ept_setup_pml2_entry(PEPT_PML2_ENTRY new_entry, std::size_t page_frame_number) noexcept
	{
		//
		// Each of the 512 collections of 512 PML2 entries is setup here
		// This will, in total, identity map every physical address from 0x0
		// to physical address 0x8000000000 (512GB of memory)
		// ((EntryGroupIndex * VMM_EPT_PML2E_COUNT) + EntryIndex) * 2MB is
		// the actual physical address we're mapping
		//
		new_entry->PageFrameNumber = page_frame_number;

		//
		// Size of 2MB page * PageFrameNumber == AddressOfRange (physical memory)
		//
		std::size_t address_of_page{ page_frame_number * SIZE_2_MB };

		//
		// To be safe, we will map the first page as UC as to not bring up any
		// kind of undefined behavior from the fixed MTRR section which we are
		// not formally recognizing (typically there is MMIO memory in the first MB)
		// 
		// I suggest reading up on the fixed MTRR section of the manual to see why the
		// first entry is likely going to need to be UC.
		//
		if (page_frame_number == 0)
		{
			new_entry->MemoryType = MEMORY_TYPE_UNCACHEABLE;
			return;
		}

		//
		// Default memory type is always WB for performance
		//
		std::size_t target_memory_type{ MEMORY_TYPE_WRITE_BACK };

		//
		// For each MTRR range
		//
		for (std::size_t current_mtrr_range{}; current_mtrr_range < ept_state->NumberOfEnabledMemoryRanges; current_mtrr_range++)
		{
			//
			// If this page's address is below or equal to the max physical address of the range
			//
			if (address_of_page <= ept_state->MemoryRanges[current_mtrr_range].PhysicalEndAddress)
			{
				//
				// And this page's last address is above or equal to the base physical address of the range
				//
				if ((address_of_page + SIZE_2_MB) - 1 >= ept_state->MemoryRanges[current_mtrr_range].PhysicalBaseAddress)
				{
					//
					// If we're here, this page fell within one of the ranges specified by the variable MTRRs
					// Therefore, we must mark this page as the same cache type exposed by the MTRR
					//
					target_memory_type = ept_state->MemoryRanges[current_mtrr_range].MemoryType;

					//
					// MTRR Precedences
					//
					if (target_memory_type == MEMORY_TYPE_UNCACHEABLE)
					{
						//
						// If this is going to be marked uncacheable, then we stop the search as UC always
						// takes precedent
						//
						break;
					}
				}
			}
		}

		//
		// Finally, commit the memory type to the entry
		//
		new_entry->MemoryType = target_memory_type;
	}

	PVMM_EPT_PAGE_TABLE allocate_and_create_identity_page_table() noexcept
	{
		//
		// Allocate address anywhere in the OS's memory space and
		// zero out all entries to ensure all unused entries are marked Not Present
		//
		PVMM_EPT_PAGE_TABLE page_table{ static_cast<decltype(page_table)>(memory::legacy::allocate_contiguous(sizeof(VMM_EPT_PAGE_TABLE))) };
		if (page_table == nullptr)
		{

			//
			// Failed to allocate memory for PageTable.
			//
			return nullptr;
		}

		//
		// Mark the first 512GB PML4 entry as present, which allows us to manage up
		// to 512GB of discrete paging structures.
		//
		page_table->PML4[0].PageFrameNumber = MmGetPhysicalAddress(&page_table->PML3[0]).QuadPart / PAGE_SIZE;
		page_table->PML4[0].ReadAccess = 1;
		page_table->PML4[0].WriteAccess = 1;
		page_table->PML4[0].ExecuteAccess = 1;

		//
		// Now mark each 1GB PML3 entry as RWX and map each to their PML2 entry
		//

		//
		// Ensure stack memory is cleard
		//
		EPT_PML3_POINTER rwx_template{ .Flags = 0 };

		//
		// Set up one 'template' RWX PML3 entry and copy it into each of the 512 PML3 entries
		// Using the same method as SimpleVisor for copying each entry using intrinsics.
		//
		rwx_template.ReadAccess = 1;
		rwx_template.WriteAccess = 1;
		rwx_template.ExecuteAccess = 1;

		//
		// Copy the template into each of 512 PML3 entry slots.
		//
		__stosq(reinterpret_cast<std::uint64_t*>(&page_table->PML3[0]), rwx_template.Flags, VMM_EPT_PML3E_COUNT);

		//
		// For each of the 512 PML3 entries
		//
		for (std::uint64_t entry_index{}; entry_index < VMM_EPT_PML3E_COUNT; entry_index++)
		{
			//
			// Map the 1GB PML3 entry to 512 PML2 (2MB) entries to describe each large page.
			// We do not manage any PML1 (4096 byte) entries and do not allocate them.
			//
			page_table->PML3[entry_index].PageFrameNumber = MmGetPhysicalAddress(&page_table->PML2[entry_index][0]).QuadPart / PAGE_SIZE;
		}

		EPT_PML2_ENTRY pml2_entry_template{ .Flags = 0 };

		//
		// All PML2 entries will be RWX and 'present'
		//
		pml2_entry_template.WriteAccess = 1;
		pml2_entry_template.ReadAccess = 1;
		pml2_entry_template.ExecuteAccess = 1;

		//
		// We are using 2MB large pages, so we must mark this 1 here
		//
		pml2_entry_template.LargePage = 1;

		//
		// For each collection of 512 PML2 entries (512 collections * 512 entries per collection),
		// mark it RWX using the same template above.
		// This marks the entries as "Present" regradless of if the actual system has memory at
		// this region or not. We will cause a fault in out EPT handler if the guest access a page
		// outside a usable range, desptie the EPT frame being present here.
		//
		__stosq(reinterpret_cast<std::uint64_t*>(&page_table->PML2[0]), pml2_entry_template.Flags, VMM_EPT_PML3E_COUNT * VMM_EPT_PML2E_COUNT);

		//
		// For each of the 512 collections of 512 2MB PML2 entries.
		//
		for (std::uint64_t entry_group_index{}; entry_group_index < VMM_EPT_PML3E_COUNT; entry_group_index++)
		{
			//
			// For each 2MB PML2 entry in the collection
			//
			for (std::uint64_t entry_index{}; entry_index < VMM_EPT_PML2E_COUNT; entry_index++)
			{
				//
				// Setup the memory type and frame number of the PML2 entry
				//
				ept_setup_pml2_entry(&page_table->PML2[entry_group_index][entry_index], (entry_group_index * VMM_EPT_PML2E_COUNT) + entry_index);
			}
		}

		return page_table;
	}

	inline bool ept_logical_processor_initialize() noexcept
	{
		PVMM_EPT_PAGE_TABLE page_table{ allocate_and_create_identity_page_table() };
		if (page_table == nullptr)
		{
			return false;
		}

		//
		// Virtual address to the page table to keep track of it for later freeing
		//
		ept_state->EptPageTable = page_table;

		//
		// For performance, we let the processor know it can cache the EPT
		//
		EPT_POINTER eptp{ .MemoryType = MEMORY_TYPE_WRITE_BACK };

		//
		// We are not utilizing the 'access' and 'dirty' flag features
		//
		eptp.EnableAccessAndDirtyFlags = false;

		//
		// Bits 5:3 (1 less than the EPT page-walk length) must be 3, indicating an EPT page-walk length of 4;
		// see Section 28.2.2
		//
		eptp.PageWalkLength = 3;

		//
		// The physical page number of the page table we will be using 
		//
		eptp.PageFrameNumber = MmGetPhysicalAddress(&page_table->PML4).QuadPart / PAGE_SIZE;

		//
		// We will write EPTP to the VMCS later.
		//
		ept_state->EptPointer = eptp;

		return true;
	}

	inline void fix_cr4_and_cr0_bits() noexcept
	{
		//
		// Fix cr0
		//
		CR_FIXED cr_fixed{ .Flags = __readmsr(IA32_VMX_CR0_FIXED0) };
		CR0 cr0{ .Flags = __readcr0() };
		cr0.Flags |= cr_fixed.Fields.Low;
		cr_fixed.Flags = __readmsr(IA32_VMX_CR0_FIXED1);
		cr0.Flags &= cr_fixed.Fields.Low;
		__writecr0(cr0.Flags);

		//
		// Fix cr4
		//
		cr_fixed.Flags = __readmsr(IA32_VMX_CR4_FIXED0);
		CR4 cr4{ .Flags = __readcr4() };
		cr4.Flags |= cr_fixed.Fields.Low;
		cr_fixed.Flags = __readmsr(IA32_VMX_CR4_FIXED1);
		cr4.Flags &= cr_fixed.Fields.Low;
		__writecr4(cr4.Flags);
	}

	PEPT_PML1_ENTRY get_pml1_entry(PVMM_EPT_PAGE_TABLE ept_page_table, std::size_t physical_address) noexcept
	{
		std::size_t directory{ ADDRMASK_EPT_PML2_INDEX(physical_address) };
		std::size_t directory_pointer{ ADDRMASK_EPT_PML3_INDEX(physical_address) };
		std::size_t pml4_entry{ ADDRMASK_EPT_PML4_INDEX(physical_address) };

		//
		// Addresses above 512GB are invalid because it is > physical address bus width
		//
		if (pml4_entry > 0)
		{
			return nullptr;
		}

		PEPT_PML2_ENTRY pml2{ &ept_page_table->PML2[directory_pointer][directory] };

		//
		// Check to ensure the page is split
		//
		if (pml2->LargePage)
		{
			return nullptr;
		}

		//
		// Conversion to get the right PageFrameNumber.
		// These pointers occupy the same place in the table and are directly convertable.
		//
		PEPT_PML2_POINTER pml2_pointer{ reinterpret_cast<PEPT_PML2_POINTER>(pml2) };

		//
		// If it is, translate to the PML1 pointer
		//
		PEPT_PML1_ENTRY pml1{ reinterpret_cast<PEPT_PML1_ENTRY>(MmGetPhysicalAddress(reinterpret_cast<void*>(pml2_pointer->PageFrameNumber * PAGE_SIZE)).QuadPart) };

		if (!pml1)
		{
			return nullptr;
		}

		//
		// Index into PML1 for that address
		//
		pml1 = &pml1[ADDRMASK_EPT_PML1_INDEX(physical_address)];

		return pml1;
	}

	inline bool allocate_vmxon_region(VIRTUAL_MACHINE_STATE* current_guest_state) noexcept
	{
		//
		// at IRQL > DISPATCH_LEVEL memory allocation routines don't work
		//
		if (KeGetCurrentIrql() > DISPATCH_LEVEL)
		{
			KfRaiseIrql(DISPATCH_LEVEL);
		}

		std::size_t vmxon_size = static_cast<std::size_t>(VMXON_SIZE) * 2;
		std::uint8_t* vmxon_region = static_cast<decltype(vmxon_region)>(memory::legacy::allocate_contiguous(vmxon_size + ALIGNMENT_PAGE_SIZE));
		if (vmxon_region == nullptr)
		{
			return false;
		}

		std::uint64_t vmxon_reion_physical_address(MmGetPhysicalAddress(vmxon_region).QuadPart);

		std::uint64_t aligned_vmxon_region{ (reinterpret_cast<std::uint64_t>(vmxon_region) + ALIGNMENT_PAGE_SIZE - 1) & ~(ALIGNMENT_PAGE_SIZE - 1)};

		//
		// 4 kb >= buffers are aligned, just a double check to ensure if it's aligned.
		//
		std::uint64_t aligned_vmxon_region_physical_address{ (vmxon_reion_physical_address + ALIGNMENT_PAGE_SIZE - 1) & ~(ALIGNMENT_PAGE_SIZE - 1) };

		//
		// get IA32_VMX_BASIC_MSR RevisionId
		//
		IA32_VMX_BASIC_REGISTER vmx_basic_msr{ .Flags = __readmsr(IA32_VMX_BASIC) };

		//
		// Changing revision identifier
		//
		*reinterpret_cast<std::uint64_t*>(aligned_vmxon_region) = vmx_basic_msr.VmcsRevisionId;

		//
		// Execute vmxon instruction
		//
		std::uint8_t vmxon_status{ __vmx_on(&aligned_vmxon_region_physical_address) };
		if (!vmxon_status)
		{
			return false;
		}

		current_guest_state->VmxonRegionPhysicalAddress = aligned_vmxon_region_physical_address;

		//
		// We save the allocated buffer (not the aligned buffer) because we want to free it in vmx termination
		//
		current_guest_state->VmxonRegionVirtualAddress = reinterpret_cast<std::uint64_t>(vmxon_region);
		return true;
	}

	inline bool allocate_vmcs_region(VIRTUAL_MACHINE_STATE* current_guest_state) noexcept
	{
		//
		// at IRQL > DISPATCH_LEVEL memory allocation routines don't work
		//
		if (KeGetCurrentIrql() > DISPATCH_LEVEL)
		{
			KfRaiseIrql(DISPATCH_LEVEL);
		}

		//
		// Allocating a 4-KByte Contigous Memory Region
		//
		std::size_t vmcs_size{ static_cast<std::size_t>(VMCS_SIZE) * 2 };
		std::uint8_t* vmcs_region{ static_cast<decltype(vmcs_region)>(memory::legacy::allocate_contiguous(vmcs_size + ALIGNMENT_PAGE_SIZE)) };
		if (vmcs_region == nullptr)
		{
			return false;
		}

		std::uint64_t vmcs_physical_address(MmGetPhysicalAddress(vmcs_region).QuadPart);
		std::uint64_t aligned_vmcs_region{ (reinterpret_cast<std::uint64_t>(vmcs_region) + ALIGNMENT_PAGE_SIZE - 1) & ~(ALIGNMENT_PAGE_SIZE - 1) };
		std::uint64_t aligned_vmcs_region_physical_address{ (vmcs_physical_address + ALIGNMENT_PAGE_SIZE - 1) & ~(ALIGNMENT_PAGE_SIZE - 1) };

		//
		// Get IA32_VMX_BASIC_MSR RevisionId
		//
		IA32_VMX_BASIC_REGISTER vmx_basic_msr{ .Flags = __readmsr(IA32_VMX_BASIC) };

		//
		// Changing Revision Identifier
		//
		*reinterpret_cast<std::uint64_t*>(aligned_vmcs_region) = vmx_basic_msr.VmcsRevisionId;

		current_guest_state->VmxonRegionPhysicalAddress = aligned_vmcs_region_physical_address;

		//
		// We save the allocated buffer (not the aligned buffer)
		// because we want to free it in vmx termination
		//
		current_guest_state->VmcsRegionVirtualAddress = reinterpret_cast<std::uint64_t>(vmcs_region);

		return true;
	}

	inline bool perform_virtualization_on_specific_core() noexcept
	{
		auto current_processor_number{ KeGetCurrentProcessorNumber() };
		VIRTUAL_MACHINE_STATE* current_vm_state{ &guest_state[current_processor_number] };

		//
		// Enabling VMX operation
		//
		enable_vmx_operation();

		//
		// Fix cr4 and cr0 bits during VMX operation
		//
		fix_cr4_and_cr0_bits();

		if (!allocate_vmxon_region(current_vm_state))
		{
			return false;
		}

		if (!allocate_vmcs_region(current_vm_state))
		{
			return false;
		}

		return true;
	}
	
	inline bool dpc_routine_perform_virtualization(KDPC* dpc [[maybe_unused]], void* deferred_context [[maybe_unused]], void* system_argument_1, void* system_argument_2) noexcept
	{
		//
		// Allocates Vmx regions for all logical cores (Vmxon region and Vmcs region)
		//
		perform_virtualization_on_specific_core();

		//
		// Wait for all	DPCs to synchornize at this point
		//
		KeSignalCallDpcSynchronize(system_argument_2);

		//
		// Mark the DPC as being complete
		//
		KeSignalCallDpcDone(system_argument_1);

		return true;
	}

	inline void boardcast_vmx_virtualization_on_all_cores() noexcept
	{
		//
		// Boardcast to all cores
		//
		KeGenericCallDpc(reinterpret_cast<PKDEFERRED_ROUTINE>(dpc_routine_perform_virtualization), nullptr);
	}

	inline bool perform_virtualization_on_all_cores() noexcept
	{
		if (!check_hypervisor_support())
		{

			//
			// VMX is not supported in this machine.
			//
			io::println("Hypervisor is not supported in this machine.");
			return false;
		}

		ept_state = static_cast<decltype(ept_state)>(memory::allocate<POOL_FLAG_NON_PAGED>(sizeof(EPT_STATE)));
		if (ept_state == nullptr)
		{

			//
			// Cannot allocate ept state, insufficient memory.
			//
			io::println("Cannot allocate ept state.");
			return false;
		}

		ept_state->HookedPagesList = memory::allocate<typename std::unordered_map<std::uint64_t, EPT_HOOKED_PAGE_DETAIL*>>();

		if (!ept_logical_processor_initialize())
		{
			//
			// There were some errors in ept_logical_processor_initialize
			//
			io::println("Failed to initialize ept logical processor.");
			return false;
		}

		//
		// Broadcast to run vmx-specific task to vitualize cores
		//
		boardcast_vmx_virtualization_on_all_cores();

		//
		// Everything is ok, let's return true
		//
		return true;
	}

	inline bool allocate_vmm_stack(int processor_id) noexcept
	{
		VIRTUAL_MACHINE_STATE* current_vm_state{ &guest_state[processor_id] };

		//
		// Allocate stack for the VM Exit Handler
		//
		current_vm_state->VmmStack = reinterpret_cast<std::uint64_t>(memory::allocate<POOL_FLAG_NON_PAGED>(VMM_STACK_SIZE));
		if (current_vm_state->VmmStack == 0)
		{
			return false;
		}

		return true;
	}

	inline bool allocate_msr_bitmap(int processor_id) noexcept
	{
		VIRTUAL_MACHINE_STATE* current_vm_state{ &guest_state[processor_id] };

		//
		// Allocate memory for MSR Bitmap
		// Should be aligned
		//
		current_vm_state->MsrBitmapVirtualAddress = reinterpret_cast<std::uint64_t>(memory::allocate<POOL_FLAG_NON_PAGED>(PAGE_SIZE));
		if (current_vm_state->MsrBitmapVirtualAddress == 0)
		{
			return false;
		}

		current_vm_state->MsrBitmapPhysicalAddress = MmGetPhysicalAddress(reinterpret_cast<void*>(current_vm_state->MsrBitmapVirtualAddress)).QuadPart;

		return true;
	}

	inline bool allocate_io_bitmaps(int processor_id) noexcept
	{
		VIRTUAL_MACHINE_STATE* current_vm_state{ &guest_state[processor_id] };

		//
		// Allocate memory for I/O Bitmap (A)
		//
		current_vm_state->IoBitmapVirtualAddressA = reinterpret_cast<std::uint64_t>(memory::allocate<POOL_FLAG_NON_PAGED>(PAGE_SIZE));
		if (current_vm_state->IoBitmapVirtualAddressA == 0)
		{
			return false;
		}

		current_vm_state->IoBitmapPhysicalAddressA = MmGetPhysicalAddress(reinterpret_cast<void*>(current_vm_state->IoBitmapVirtualAddressA)).QuadPart;

		//
		// Allocate memory for I/O Bitmap (B)
		//
		current_vm_state->IoBitmapVirtualAddressB = reinterpret_cast<std::uint64_t>(memory::allocate<POOL_FLAG_NON_PAGED>(PAGE_SIZE));
		if (current_vm_state->IoBitmapVirtualAddressB == 0)
		{
			return false;
		}

		current_vm_state->IoBitmapPhysicalAddressB = MmGetPhysicalAddress(reinterpret_cast<void*>(current_vm_state->IoBitmapVirtualAddressB)).QuadPart;

		return true;
	}

	std::uint64_t* allocate_invalid_msr_bitmap()
	{
		std::uint64_t* invalid_msr_bitmap{ static_cast<std::uint64_t*>(memory::allocate<POOL_FLAG_NON_PAGED>(0x1000 / 0x8)) };
		if (invalid_msr_bitmap == nullptr)
		{
			return nullptr;
		}

		for (std::size_t i{}; i < 0x1000; i++)
		{
			__try
			{
				__readmsr(static_cast<unsigned long>(i));
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				BITMAP_ENTRY(i, invalid_msr_bitmap) |= (1ULL << BITMAP_SHIFT(i));
			}
		}

		return invalid_msr_bitmap;
	}

	inline bool clear_vmcs_state(VIRTUAL_MACHINE_STATE* current_guest_state)
	{
		std::uint8_t vmclear_status{ __vmx_vmclear(&current_guest_state->VmcsRegionPhysicalAddress) };

		if (vmclear_status)
		{
			__vmx_off();
			return false;
		}

		return true;
	}

	inline bool load_vmcs(VIRTUAL_MACHINE_STATE* current_guest_state)
	{
		std::uint8_t vmptrld_status{ __vmx_vmptrld(&current_guest_state->VmcsRegionPhysicalAddress) };
		if (vmptrld_status)
		{
			return false;
		}
		
		return true;
	}

	bool get_segment_descriptor(std::uint8_t* gdt_base, std::uint16_t selector, PVMX_SEGMENT_SELECTOR segment_selector) noexcept
	{
		if (segment_selector == nullptr)
		{
			return false;
		}

		#define SELECTOR_TABLE_LDT 0x1
		#define SELECTOR_TABLE_GDT 0x0

		SEGMENT_SELECTOR seg_selector{ .Flags = selector };

		//
		// Ignore IDT
		//
		if (selector == 0x0 || seg_selector.Table != SELECTOR_TABLE_GDT)
		{
			return false;
		}

		SEGMENT_DESCRIPTOR_32* descriptor_table_32{ reinterpret_cast<SEGMENT_DESCRIPTOR_32*>(gdt_base) };
		SEGMENT_DESCRIPTOR_32* descriptor32{ &descriptor_table_32[seg_selector.Index] };

		segment_selector->Selector = selector;
		segment_selector->Limit = __segmentlimit(selector);

		segment_selector->Base = static_cast<std::uint64_t>(descriptor32->BaseAddressLow) | static_cast<std::uint64_t>(descriptor32->BaseAddressMiddle) << 16 | 
			static_cast<std::uint64_t>(descriptor32->BaseAddressHigh) << 24;

		segment_selector->Attributes.Flags = get_access_right(selector) >> 8;

		if (seg_selector.Table == 0 && seg_selector.Index == 0)
		{
			segment_selector->Attributes.Unusable = true;
		}

		if (descriptor32->Type == SEGMENT_DESCRIPTOR_TYPE_TSS_BUSY || descriptor32->Type == SEGMENT_DESCRIPTOR_TYPE_CALL_GATE)
		{
			//
			// This is a TSS or callgate etc, save the base high part
			//
			std::uint64_t segment_limit_high{ *reinterpret_cast<std::uint64_t*>(reinterpret_cast<std::uint8_t*>(descriptor32) + 8) };
			segment_selector->Base = (segment_selector->Base & 0xFFFFFFFF) | (segment_limit_high << 32);
		}

		if (segment_selector->Attributes.Granularity)
		{
			//
			// 4096-bit granularity is enabled for this segment, scale the limit
			//
			segment_selector->Limit = (segment_selector->Limit << 12) + 0xFFFF;
		}

		return true;
	}

	inline void fill_guest_selector_data(void* gdt_base, unsigned long segment_register, std::uint16_t selector) noexcept
	{
		VMX_SEGMENT_SELECTOR segment_selector{};

		get_segment_descriptor(static_cast<std::uint8_t*>(gdt_base), selector, &segment_selector);

		if (selector == 0x0)
		{
			segment_selector.Attributes.Unusable = true;
		}

		__vmx_vmwrite(static_cast<std::size_t>(VMCS_GUEST_ES_SELECTOR) + static_cast<std::size_t>(segment_register) * 2, selector);
		__vmx_vmwrite(static_cast<std::size_t>(VMCS_GUEST_ES_LIMIT) + static_cast<std::size_t>(segment_register) * 2, segment_selector.Limit);
		__vmx_vmwrite(static_cast<std::size_t>(VMCS_GUEST_ES_ACCESS_RIGHTS) + static_cast<std::size_t>(segment_register) * 2, segment_selector.Attributes.Flags);
		__vmx_vmwrite(static_cast<std::size_t>(VMCS_GUEST_ES_BASE) + static_cast<std::size_t>(segment_register) * 2, segment_selector.Base);
	}

	unsigned long adjust_controls(unsigned long ctl, unsigned long msr) noexcept
	{
		MSR msr_value{ .Flags = __readmsr(msr) };

		ctl &= msr_value.Fields.High;
		ctl |= msr_value.Fields.Low;

		return ctl;
	}

	inline std::uint64_t find_system_directory_table() noexcept
	{
		//
		// Return CR3 of the system process.
		//
		NT_KPROCESS* system_process = reinterpret_cast<NT_KPROCESS*>(PsInitialSystemProcess);
		return system_process->DirectoryTableBase;
	}

	bool setup_vmcs(VIRTUAL_MACHINE_STATE* current_guest_state, void* guest_stack) noexcept
	{
		//
		// Reading IA32_VMX_BASIC_MSR
		//
		IA32_VMX_BASIC_REGISTER vmx_basic_msr{ .Flags = __readmsr(IA32_VMX_BASIC) };

		__vmx_vmwrite(VMCS_HOST_ES_SELECTOR, get_es() & 0xF8);
		__vmx_vmwrite(VMCS_HOST_CS_SELECTOR, get_cs() & 0xF8);
		__vmx_vmwrite(VMCS_HOST_SS_SELECTOR, get_ss() & 0xF8);
		__vmx_vmwrite(VMCS_HOST_DS_SELECTOR, get_ds() & 0xF8);
		__vmx_vmwrite(VMCS_HOST_FS_SELECTOR, get_fs() & 0xF8);
		__vmx_vmwrite(VMCS_HOST_GS_SELECTOR, get_gs() & 0xF8);
		__vmx_vmwrite(VMCS_HOST_TR_SELECTOR, get_tr() & 0xF8);

		//
		// Setting the link pointer to the required value for 4KB VMCS
		//
		__vmx_vmwrite(VMCS_GUEST_VMCS_LINK_POINTER, ~0ULL);
		
		__vmx_vmwrite(VMCS_GUEST_DEBUGCTL, __readmsr(IA32_DEBUGCTL) & 0xFFFFFFFF);
		__vmx_vmwrite(VMCS_GUEST_DEBUGCTL_HIGH, __readmsr(IA32_DEBUGCTL) >> 32);

		__vmx_vmwrite(VMCS_CTRL_TSC_OFFSET, 0);

		__vmx_vmwrite(VMCS_CTRL_PAGEFAULT_ERROR_CODE_MASK, 0);
		__vmx_vmwrite(VMCS_CTRL_PAGEFAULT_ERROR_CODE_MATCH, 0);

		__vmx_vmwrite(VMCS_CTRL_VMEXIT_MSR_STORE_COUNT, 0);
		__vmx_vmwrite(VMCS_CTRL_VMEXIT_MSR_LOAD_COUNT, 0);

		__vmx_vmwrite(VMCS_CTRL_VMENTRY_MSR_LOAD_COUNT, 0);
		__vmx_vmwrite(VMCS_CTRL_VMENTRY_INTERRUPTION_INFORMATION_FIELD, 0);

		std::uint64_t gdt_base{ get_gdt_base() };

		fill_guest_selector_data(reinterpret_cast<void*>(gdt_base), SEGMENT_REGISTERS::ES, get_es());
		fill_guest_selector_data(reinterpret_cast<void*>(gdt_base), SEGMENT_REGISTERS::CS, get_cs());
		fill_guest_selector_data(reinterpret_cast<void*>(gdt_base), SEGMENT_REGISTERS::SS, get_ss());
		fill_guest_selector_data(reinterpret_cast<void*>(gdt_base), SEGMENT_REGISTERS::DS, get_ds());
		fill_guest_selector_data(reinterpret_cast<void*>(gdt_base), SEGMENT_REGISTERS::FS, get_fs());
		fill_guest_selector_data(reinterpret_cast<void*>(gdt_base), SEGMENT_REGISTERS::GS, get_gs());
		fill_guest_selector_data(reinterpret_cast<void*>(gdt_base), SEGMENT_REGISTERS::LDTR, get_ldtr());
		fill_guest_selector_data(reinterpret_cast<void*>(gdt_base), SEGMENT_REGISTERS::TR, get_tr());

		__vmx_vmwrite(VMCS_GUEST_FS_BASE, __readmsr(IA32_FS_BASE));
		__vmx_vmwrite(VMCS_GUEST_GS_BASE, __readmsr(IA32_GS_BASE));

		unsigned long cpu_based_vm_execute_controls{ adjust_controls(CPU_BASED_ACTIVATE_IO_BITMAP | CPU_BASED_ACTIVATE_MSR_BITMAP | CPU_BASED_ACTIVATE_SECONDARY_CONTROLS,
											  vmx_basic_msr.VmxControls ? IA32_VMX_TRUE_PROCBASED_CTLS : IA32_VMX_PROCBASED_CTLS) };

		__vmx_vmwrite(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, cpu_based_vm_execute_controls);

		unsigned long secondary_processor_vm_execute_controls{ adjust_controls(CPU_BASED_CTL2_RDTSCP |
															CPU_BASED_CTL2_ENABLE_EPT | CPU_BASED_CTL2_ENABLE_INVPCID |
															CPU_BASED_CTL2_ENABLE_XSAVE_XRSTORS | CPU_BASED_CTL2_ENABLE_VPID,
														IA32_VMX_PROCBASED_CTLS2) };

		__vmx_vmwrite(VMCS_CTRL_SECONDARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, secondary_processor_vm_execute_controls);

		__vmx_vmwrite(VMCS_CTRL_PIN_BASED_VM_EXECUTION_CONTROLS, adjust_controls(0, vmx_basic_msr.VmxControls ? IA32_VMX_TRUE_PINBASED_CTLS : IA32_VMX_PINBASED_CTLS));

		__vmx_vmwrite(VMCS_CTRL_VMEXIT_CONTROLS, adjust_controls(VM_EXIT_HOST_ADDR_SPACE_SIZE, vmx_basic_msr.VmxControls ? IA32_VMX_TRUE_EXIT_CTLS : IA32_VMX_EXIT_CTLS));

		__vmx_vmwrite(VMCS_CTRL_VMENTRY_CONTROLS, adjust_controls(VM_ENTRY_IA32E_MODE, vmx_basic_msr.VmxControls ? IA32_VMX_TRUE_ENTRY_CTLS : IA32_VMX_ENTRY_CTLS));

		__vmx_vmwrite(VMCS_CTRL_CR0_GUEST_HOST_MASK, 0);
		__vmx_vmwrite(VMCS_CTRL_CR4_GUEST_HOST_MASK, 0);

		__vmx_vmwrite(VMCS_CTRL_CR0_READ_SHADOW, 0);
		__vmx_vmwrite(VMCS_CTRL_CR4_READ_SHADOW, 0);

		__vmx_vmwrite(VMCS_GUEST_CR0, __readcr0());
		__vmx_vmwrite(VMCS_GUEST_CR3, __readcr3());
		__vmx_vmwrite(VMCS_GUEST_CR4, __readcr4());

		__vmx_vmwrite(VMCS_GUEST_DR7, 0x400);

		__vmx_vmwrite(VMCS_HOST_CR0, __readcr0());
		__vmx_vmwrite(VMCS_HOST_CR4, __readcr4());

		//
		// Because we may be executing in an arbitrary user-mode, process as part
		// of the DPC interrupt we execute in We have to save Cr3, for VMCS_HOST_CR3
		//

		__vmx_vmwrite(VMCS_HOST_CR3, find_system_directory_table());

		__vmx_vmwrite(VMCS_GUEST_GDTR_BASE, get_gdt_base());
		__vmx_vmwrite(VMCS_GUEST_IDTR_BASE, get_idt_base());

		__vmx_vmwrite(VMCS_GUEST_GDTR_LIMIT, get_gdt_limit());
		__vmx_vmwrite(VMCS_GUEST_IDTR_LIMIT, get_idt_limit());

		__vmx_vmwrite(VMCS_GUEST_RFLAGS, get_rflags());

		__vmx_vmwrite(VMCS_GUEST_SYSENTER_CS, __readmsr(IA32_SYSENTER_CS));
		__vmx_vmwrite(VMCS_GUEST_SYSENTER_EIP, __readmsr(IA32_SYSENTER_EIP));
		__vmx_vmwrite(VMCS_GUEST_SYSENTER_ESP, __readmsr(IA32_SYSENTER_ESP));

		VMX_SEGMENT_SELECTOR segment_selector{};

		get_segment_descriptor(reinterpret_cast<std::uint8_t*>(get_gdt_base()), get_tr(), &segment_selector);
		__vmx_vmwrite(VMCS_HOST_TR_BASE, segment_selector.Base);

		__vmx_vmwrite(VMCS_HOST_FS_BASE, __readmsr(IA32_FS_BASE));
		__vmx_vmwrite(VMCS_HOST_GS_BASE, __readmsr(IA32_GS_BASE));

		__vmx_vmwrite(VMCS_HOST_GDTR_BASE, get_gdt_base());
		__vmx_vmwrite(VMCS_HOST_IDTR_BASE, get_idt_base());

		__vmx_vmwrite(VMCS_HOST_SYSENTER_CS, __readmsr(IA32_SYSENTER_CS));
		__vmx_vmwrite(VMCS_HOST_SYSENTER_EIP, __readmsr(IA32_SYSENTER_EIP));
		__vmx_vmwrite(VMCS_HOST_SYSENTER_ESP, __readmsr(IA32_SYSENTER_ESP));

		//
		// Set MSR Bitmaps
		//
		__vmx_vmwrite(VMCS_CTRL_MSR_BITMAP_ADDRESS, current_guest_state->MsrBitmapPhysicalAddress);

		//
		// Set I/O Bitmaps
		//
		__vmx_vmwrite(VMCS_CTRL_IO_BITMAP_A_ADDRESS, current_guest_state->IoBitmapPhysicalAddressA);
		__vmx_vmwrite(VMCS_CTRL_IO_BITMAP_B_ADDRESS, current_guest_state->IoBitmapPhysicalAddressB);

		//
		// Set up EPT
		//
		__vmx_vmwrite(VMCS_CTRL_EPT_POINTER, ept_state->EptPointer.Flags);

		//
		// Set up VPID

		//
		// For all processors, we will use a VPID = 1. This allows the processor to separate caching
		//  of EPT structures away from the regular OS page translation tables in the TLB.
		//
		__vmx_vmwrite(VIRTUAL_PROCESSOR_ID, VPID_TAG);

		//
		//setup guest rsp
		//
		__vmx_vmwrite(VMCS_GUEST_RSP, reinterpret_cast<std::uint64_t>(guest_stack));

		//
		//setup guest rip
		//
		__vmx_vmwrite(VMCS_GUEST_RIP, reinterpret_cast<std::uint64_t>(restore_hypervisor_state));

		//
		// Stack should be aligned to 16 because we wanna save XMM and FPU registers and those instructions
		// needs alignment to 16
		//
		void* host_rsp = reinterpret_cast<void*>(current_guest_state->VmmStack + VMM_STACK_SIZE - 1);
		host_rsp = reinterpret_cast<void*>(reinterpret_cast<std::uint64_t>(host_rsp) & ~(16 - 1));
		__vmx_vmwrite(VMCS_HOST_RSP, reinterpret_cast<std::size_t>(host_rsp));
		__vmx_vmwrite(VMCS_HOST_RIP, reinterpret_cast<std::size_t>(vm_exit_handler));

		return true;
	}

	void resume_to_next_instruction() noexcept
	{
		std::uint64_t current_rip{};
		std::size_t exit_instruction_length{};

		__vmx_vmread(VMCS_GUEST_RIP, &current_rip);
		__vmx_vmread(VMCS_VMEXIT_INSTRUCTION_LENGTH, &exit_instruction_length);

		std::uint64_t resume_rip{ current_rip + exit_instruction_length };

		__vmx_vmwrite(VMCS_GUEST_RIP, resume_rip);
	}

	bool hook_handle_hooked_page(PGUEST_REGS regs [[maybe_unused]], EPT_HOOKED_PAGE_DETAIL* hooked_entry_detail, VMX_EXIT_QUALIFICATION_EPT_VIOLATION violation_qualification,
		std::size_t physical_address) noexcept
	{
		std::uint64_t aligned_virtual_address{ reinterpret_cast<std::uint64_t>(PAGE_ALIGN(hooked_entry_detail->VirtualAddress)) };
		std::uint64_t aligned_physical_address{ reinterpret_cast<std::uint64_t>(PAGE_ALIGN(physical_address)) };

		//
		// Let's read the exact address that was accessed
		//
		std::uint64_t exact_accessed_virtual_address{ aligned_virtual_address + physical_address - aligned_physical_address };

		//
		// Create the temporary context
		//
		EPT_HOOKS_TEMPORARY_CONTEXT context{ .PhysicalAddress = physical_address, .VirtualAddress = exact_accessed_virtual_address };

		if (!violation_qualification.EptExecutable && violation_qualification.ExecuteAccess)
		{
			std::uint64_t guest_rip{};

			//
			// Reading guest's RIP
			//
			__vmx_vmread(VMCS_GUEST_RIP, &guest_rip);
		}
		else if(!violation_qualification.EptWriteable && violation_qualification.WriteAccess)
		{

		}
		else if (!violation_qualification.EptReadable && violation_qualification.ReadAccess)
		{

		}
		else
		{
			//
			// There was an unexpected ept violation
			//
			return false;
		}

		//
		// Means that restore the Entry to the previous state after current instruction executed in the guest
		//
		return true;
	}

	inline std::uint8_t ept_invept(std::uint32_t type, INVEPT_DESCRIPTOR* descriptor) noexcept
	{
		if (descriptor == nullptr)
		{
			INVEPT_DESCRIPTOR zero_descriptor{};
			descriptor = &zero_descriptor;
		}

		return _invept(type, descriptor);
	}

	inline std::uint8_t ept_invept_single_context(std::uint64_t ept_pointer) noexcept
	{
		INVEPT_DESCRIPTOR descriptor{ .EptPointer = ept_pointer, .Reserved = 0 };
		return ept_invept(INVEPT_TYPE::InveptSingleContext, &descriptor);
	}

	inline std::uint8_t ept_invept_all_contexts() noexcept
	{
		return ept_invept(INVEPT_TYPE::InveptAllContext, nullptr);
	}

	void ept_set_pml1_and_invalidate_tlb(PEPT_PML1_ENTRY entry_address, EPT_PML1_ENTRY entry_value, INVEPT_TYPE invalidation_type) noexcept
	{
		KIRQL old_irql{};

		//
		// Acquire the lock
		//
		KeAcquireSpinLock(&Pml1ModificationAndInvalidationLock, &old_irql);

		//
		// Set the value
		//
		entry_address->Flags = entry_value.Flags;

		//
		// Invalidate the cache
		//
		if (invalidation_type == INVEPT_TYPE::InveptSingleContext)
		{
			ept_invept_single_context(ept_state->EptPointer.Flags);
		}
		else
		{
			ept_invept_all_contexts();
		}

		//
		// Release the lock
		//
		KeReleaseSpinLock(&Pml1ModificationAndInvalidationLock, old_irql);
	}

	void set_monitor_trap_flag(bool set) noexcept
	{
		std::size_t cpu_based_vm_exec_controls{};

		//
		// Read the previous flags
		//
		__vmx_vmread(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, &cpu_based_vm_exec_controls);

		if (set)
		{
			cpu_based_vm_exec_controls |= CPU_BASED_MONITOR_TRAP_FLAG;
		}
		else
		{
			cpu_based_vm_exec_controls &= ~CPU_BASED_MONITOR_TRAP_FLAG;
		}

		//
		// Set the new value
		//
		__vmx_vmwrite(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, cpu_based_vm_exec_controls);
	}

	void protected_apply_set_external_interrupting_exiting(bool set, PROTECTED_HV_RESOURCES_PASSING_OVERS pass_over) noexcept
	{
		//
		// The protected checks are only performed if the "set" is "false", 
		// because if sb wants to set it to "TRUE" then we're no need to
		// worry about it as it remains enabled
		//
		if (!set)
		{
			std::uint32_t current_core_id{};

			//
			// Check if the integrity check is because of clearing
			// events or not, if it's for clearing events, the debugger
			// will automatically set
			//

			if ((pass_over & PROTECTED_HV_RESOURCES_PASSING_OVERS::PASSING_OVER_INTERRUPT_EVENTS) == 0)
			{
				current_core_id = KeGetCurrentProcessorNumber();
			}

			//
			// Check if it should remain active for thread or process changing or not
			//
			if (guest_state[current_core_id].DebuggingState.ThreadOrProcessTracingDetails.InterceptClockInterruptsForThreadChange ||
				guest_state[current_core_id].DebuggingState.ThreadOrProcessTracingDetails.InterceptClockInterruptsForProcessChange)
			{
				return;
			}
		}

		//
		// In order to enable External Interrupt Exiting we have to set
		// PIN_BASED_VM_EXECUTION_CONTROLS_EXTERNAL_INTERRUPT in vmx
		// pin-based controls (PIN_BASED_VM_EXEC_CONTROL) and also
		// we should enable VM_EXIT_ACK_INTR_ON_EXIT on vmx vm-exit
		// controls (VMCS_CTRL_VMEXIT_CONTROLS), also this function might not
		// always be successful if the guest is not in the interruptible
		// state so it wait for and interrupt-window exiting to re-inject
		// the interrupt into the guest
		//

		std::size_t pin_based_controls{};
		std::size_t vmexit_controls{};

		//
		// Read the previous flags
		//
		__vmx_vmread(VMCS_CTRL_PIN_BASED_VM_EXECUTION_CONTROLS, &pin_based_controls);
		__vmx_vmread(VMCS_CTRL_VMEXIT_CONTROLS, &vmexit_controls);

		if (set)
		{
			pin_based_controls |= PIN_BASED_VM_EXECUTION_CONTROLS_EXTERNAL_INTERRUPT;
			vmexit_controls |= VM_EXIT_ACK_INTR_ON_EXIT;
		}
		else
		{
			pin_based_controls &= ~PIN_BASED_VM_EXECUTION_CONTROLS_EXTERNAL_INTERRUPT;
			vmexit_controls &= ~VM_EXIT_ACK_INTR_ON_EXIT;
		}

		//
		// Set the new value
		//
		__vmx_vmwrite(VMCS_CTRL_PIN_BASED_VM_EXECUTION_CONTROLS, pin_based_controls);
		__vmx_vmwrite(VMCS_CTRL_VMEXIT_CONTROLS, vmexit_controls);
	}

	inline void protected_set_external_interrupt_exiting(bool set) noexcept
	{
		protected_apply_set_external_interrupting_exiting(set, PROTECTED_HV_RESOURCES_PASSING_OVERS::PASSING_OVER_NONE);
	}

	inline void set_external_interrupt_exiting(bool set) noexcept
	{
		//
		// This is a wrapper to perform extra checks
		//
		protected_set_external_interrupt_exiting(set);
	}
	
	inline void set_interrupt_window_exiting(bool set) noexcept
	{
		std::size_t cpu_based_vm_exec_controls{};

		//
		// Read the previous flags
		//
		__vmx_vmread(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, &cpu_based_vm_exec_controls);
		
		//
		// Interrupt-window exiting
		//
		if (set)
		{
			cpu_based_vm_exec_controls |= CPU_BASED_VIRTUAL_INTR_PENDING;
		}
		else
		{
			cpu_based_vm_exec_controls &= ~CPU_BASED_VIRTUAL_INTR_PENDING;
		}

		//
		// Set the new value
		//
		__vmx_vmwrite(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, cpu_based_vm_exec_controls);
	}

	bool handle_ept_page_hook_exit(PGUEST_REGS regs, VMX_EXIT_QUALIFICATION_EPT_VIOLATION violation_qualification, std::uint64_t guest_physical_address) noexcept
	{
		bool handled{};
		auto result{ ept_state->HookedPagesList->find(guest_physical_address) };
		if (result != ept_state->HookedPagesList->end())
		{
			EPT_HOOKED_PAGE_DETAIL* hooked_entry{ result->second };
			
			//
			// We found an address that matches the details
			//

			//
			// Returning true means that the caller should return to the ept state to
			// the previous state when this instruction is executed
			// by setting the Monitor Trap Flag. Return false means that nothing special
			// for the caller to do
			//
			if (hook_handle_hooked_page(regs, hooked_entry, violation_qualification, guest_physical_address))
			{
				//
				// Restore to its original entry for one instruction
				//
				ept_set_pml1_and_invalidate_tlb(hooked_entry->EntryAddress, hooked_entry->OriginalEntry, INVEPT_TYPE::InveptSingleContext);

				//
				// Next we have to save the current hooked entry to restore on the next instruction's vm-exit
				//
				guest_state[KeGetCurrentProcessorNumber()].MtfEptHookRestorePoint = hooked_entry;

				set_monitor_trap_flag(true);

				//
				// The following codes are added because we realized if the execution takes long then
				// the execution might be switched to another routines, thus, MTF might conclude on
				// another routine and we might (and will) trigger the same instruction soon
				//

				//
				// Change guest interrupt-state
				//
				set_external_interrupt_exiting(true);

				//
				// Do not vm-exit on interrupt windows
				//
				set_interrupt_window_exiting(false);

				//
				// Indicate that we should enable external interruts and configure external interrupt
				// window exiting somewhere at MTF
				//
				guest_state[KeGetCurrentProcessorNumber()].DebuggingState.EnableExternalInterruptsOnContinueMtf = true;
			}

			handled = true;
		}

		guest_state[KeGetCurrentProcessorNumber()].IncrementRip = false;

		return handled;
	}

	bool handle_ept_violation(PGUEST_REGS regs, unsigned long exit_qualification, std::uint64_t guest_physical_address) noexcept
	{
		VMX_EXIT_QUALIFICATION_EPT_VIOLATION violation_qualification{ .Flags = exit_qualification };

		if (handle_ept_page_hook_exit(regs, violation_qualification, guest_physical_address))
		{
			//
			// Handled by page hook code
			//
			return true;
		}

		return false;
	}

	extern "C" bool vmx_vmexit_handler(PGUEST_REGS guest_regs [[maybe_unused]]) noexcept
	{
		auto current_processor_index{ KeGetCurrentProcessorNumber() };
		VIRTUAL_MACHINE_STATE* current_guest_state{ &guest_state[current_processor_index] };

		//
		// Indicates we are in Vmx root mode in this logical core
		//
		current_guest_state->IsOnVmxRootMode = true;

		std::size_t exit_reason{};

		//
		// Read the exit reason and exit qualification
		//
		__vmx_vmread(VMCS_EXIT_REASON, &exit_reason);

		exit_reason &= 0xFFFF;

		//
		// Increase the RIP by default
		//
		current_guest_state->IncrementRip = true;

		std::uint64_t guest_rip{};
		//
		// Save the current rip
		//
		__vmx_vmread(VMCS_GUEST_RIP, &guest_rip);
		current_guest_state->LastVmexitRip = guest_rip;

		//
		// Set the rsp in general purpose registers structure
		//
		__vmx_vmread(VMCS_GUEST_RSP, &guest_rip);

		std::uint64_t exit_qulification{};

		//
		// Read the exit qualification
		//
		__vmx_vmread(VMCS_EXIT_QUALIFICATION, &exit_qulification);

		
		switch (exit_reason)
		{
			case VMX_EXIT_REASON_EPT_VIOLATION:
			{
				std::uint64_t guest_physical_address{};

				//
				// Reading guest physical address
				//
				__vmx_vmread(VMCS_GUEST_PHYSICAL_ADDRESS, &guest_physical_address);

				handle_ept_violation(guest_regs, static_cast<unsigned long>(exit_qulification), guest_physical_address);
			}
				break;
			default:
				break;
		}
		

		//
		// Check whether we need to increment the guest's ip or not
		// Also, we should not increment rip if a vmxoff executed
		//
		if (!current_guest_state->VmxoffState.IsVmxoffExecuted && current_guest_state->IncrementRip)
		{
			resume_to_next_instruction();
		}

		//
		// Set indicator of Vmx non root mode to false
		//
		current_guest_state->IsOnVmxRootMode = false;

		//
		// Check for vmxoff request
		//
		if (current_guest_state->VmxoffState.IsVmxoffExecuted)
		{
			return true;
		}

		//
		// By default it's false, if we want to exit vmx then it's true
		//
		return false;
	}

	extern "C" std::uint64_t vmx_return_stack_pointer_for_vmxoff() noexcept
	{
		return guest_state[KeGetCurrentProcessorNumber()].VmxoffState.GuestRsp;
	}

	extern "C" std::uint64_t vmx_return_instruction_pointer_for_vmxoff() noexcept
	{
		return guest_state[KeGetCurrentProcessorNumber()].VmxoffState.GuestRip;
	}

	extern "C" void vmx_vmresume() noexcept
	{
		__vmx_vmresume();

		//
		// if vmresume succeed will never be here
		//
		
		std::uint64_t error_code{};
		__vmx_vmread(VMCS_VM_INSTRUCTION_ERROR, &error_code);
		__vmx_off();
	}

	extern "C" bool virtualize_current_system(void* guest_stack) noexcept
	{
		VIRTUAL_MACHINE_STATE* current_vm_state{ &guest_state[KeGetCurrentProcessorNumber()] };

		//
		// Clear the VMCS State
		//
		if (!clear_vmcs_state(current_vm_state))
		{
			return false;
		}

		//
		// Load VMCS (Set the Current VMCS)
		//

		if (!load_vmcs(current_vm_state))
		{
			return false;
		}

		setup_vmcs(current_vm_state, guest_stack);

		current_vm_state->HasLaunched = true;

		__vmx_vmlaunch();

		//
		// If Vmlaunch succeed will never be here
		//

		//
		// If failed, then indicate that current core is not currently virtualized
		//
		current_vm_state->HasLaunched = false;

		//
		// Execucte vmxoff
		//
		__vmx_off();

		return false;
	}

	void dpc_routine_initialize_guest(KDPC* dpc [[maybe_unused]], void* deferred_context [[maybe_unused]], void* system_argument_1, void* system_argument_2) noexcept
	{
		//
		// Save the vmx state and prepare vmcs setup and finally execute vmlaunch instruction
		//
		save_hypervisor_state();

		//
		// Wait for all DPCs to synchronize at this point
		//
		KeSignalCallDpcSynchronize(system_argument_2);

		//
		// Mark the DPC as being complete
		//
		KeSignalCallDpcDone(system_argument_1);
	}

	bool initialize_hypervisor() noexcept
	{
		std::size_t guest_size = sizeof(VIRTUAL_MACHINE_STATE) * KeQueryActiveProcessorCount(0);

		guest_state = static_cast<VIRTUAL_MACHINE_STATE*>(memory::allocate<POOL_FLAG_NON_PAGED>(guest_size));

		//
		// Initiating EPTP and VMX
		//
		if (!perform_virtualization_on_all_cores())
		{
			//
			// there was error somewhere in initializing
			//
			io::println("Failed to perform virtualization on all cores.");
			return false;
		}

		auto logical_processor_count{ KeQueryActiveProcessorCount(0) };

		for (std::size_t processor_id{}; processor_id < logical_processor_count; processor_id++)
		{
			//
			// Allocating VMM Stack
			//
			if (!allocate_vmm_stack(static_cast<int>(processor_id)))
			{
				//
				// Some error in allocating Vmm Stack
				//
				io::println("Failed to allocate vmm stack");
				return false;
			}

			//
			// Allocating MSR Bit
			//
			if (!allocate_msr_bitmap(static_cast<int>(processor_id)))
			{
				//
				// Some error in allocating Msr Bitmaps
				//
				io::println("Failed to allocate msr bitmap");
				return false;
			}

			//
			// Allocating I/O Bit
			//
			if (!allocate_io_bitmaps(static_cast<int>(processor_id)))
			{
				//
				// Some error in allocating I/O Bitmaps
				//
				io::println("Failed to allocate io bitmaps");
				return false;
			}
		}

		//
		// Create a bitmap of the MSRs that cause #GP
		//
		msr_bitmap_invalid_msrs = allocate_invalid_msr_bitmap();
		if (msr_bitmap_invalid_msrs == nullptr)
		{
			io::println("Failed to allocate invalid msr bitmap");
			return false;
		}

		//
		// As we want to support more than 32 processor (64 logical-core)
		// we let windows execute our routine for us
		//
		KeGenericCallDpc(dpc_routine_initialize_guest, nullptr);

		return true;
	}
}