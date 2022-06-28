#pragma once

namespace virtualization
{
	/**
	 * @brief VPID Tag
	 *
	 */
	#define VPID_TAG 0x1

	/**
	 * @brief VM-entry Control Bits
	 *
	 */
	#define VM_ENTRY_LOAD_DEBUG_CONTROLS        0x00000004
	#define VM_ENTRY_IA32E_MODE                 0x00000200
	#define VM_ENTRY_SMM                        0x00000400
	#define VM_ENTRY_DEACT_DUAL_MONITOR         0x00000800
	#define VM_ENTRY_LOAD_IA32_PERF_GLOBAL_CTRL 0x00002000
	#define VM_ENTRY_LOAD_IA32_PAT              0x00004000
	#define VM_ENTRY_LOAD_IA32_EFER             0x00008000

	/**
     * @brief VM-exit Control Bits
     *
     */
	#define VM_EXIT_SAVE_DEBUG_CONTROLS        0x00000004
	#define VM_EXIT_HOST_ADDR_SPACE_SIZE       0x00000200
	#define VM_EXIT_LOAD_IA32_PERF_GLOBAL_CTRL 0x00001000
	#define VM_EXIT_ACK_INTR_ON_EXIT           0x00008000
	#define VM_EXIT_SAVE_IA32_PAT              0x00040000
	#define VM_EXIT_LOAD_IA32_PAT              0x00080000
	#define VM_EXIT_SAVE_IA32_EFER             0x00100000
	#define VM_EXIT_LOAD_IA32_EFER             0x00200000
	#define VM_EXIT_SAVE_VMX_PREEMPTION_TIMER  0x00400000

	/**
     * @brief CPU-Based Controls
     *
     */
	#define CPU_BASED_VIRTUAL_INTR_PENDING        0x00000004
	#define CPU_BASED_USE_TSC_OFFSETING           0x00000008
	#define CPU_BASED_HLT_EXITING                 0x00000080
	#define CPU_BASED_INVLPG_EXITING              0x00000200
	#define CPU_BASED_MWAIT_EXITING               0x00000400
	#define CPU_BASED_RDPMC_EXITING               0x00000800
	#define CPU_BASED_RDTSC_EXITING               0x00001000
	#define CPU_BASED_CR3_LOAD_EXITING            0x00008000
	#define CPU_BASED_CR3_STORE_EXITING           0x00010000
	#define CPU_BASED_CR8_LOAD_EXITING            0x00080000
	#define CPU_BASED_CR8_STORE_EXITING           0x00100000
	#define CPU_BASED_TPR_SHADOW                  0x00200000
	#define CPU_BASED_VIRTUAL_NMI_PENDING         0x00400000
	#define CPU_BASED_MOV_DR_EXITING              0x00800000
	#define CPU_BASED_UNCOND_IO_EXITING           0x01000000
	#define CPU_BASED_ACTIVATE_IO_BITMAP          0x02000000
	#define CPU_BASED_MONITOR_TRAP_FLAG           0x08000000
	#define CPU_BASED_ACTIVATE_MSR_BITMAP         0x10000000
	#define CPU_BASED_MONITOR_EXITING             0x20000000
	#define CPU_BASED_PAUSE_EXITING               0x40000000
	#define CPU_BASED_ACTIVATE_SECONDARY_CONTROLS 0x80000000

	/**
	 * @brief Secondary CPU-Based Controls
	 *
	 */
	#define CPU_BASED_CTL2_ENABLE_EPT                 0x2
	#define CPU_BASED_CTL2_RDTSCP                     0x8
	#define CPU_BASED_CTL2_ENABLE_VPID                0x20
	#define CPU_BASED_CTL2_UNRESTRICTED_GUEST         0x80
	#define CPU_BASED_CTL2_VIRTUAL_INTERRUPT_DELIVERY 0x200
	#define CPU_BASED_CTL2_ENABLE_INVPCID             0x1000
	#define CPU_BASED_CTL2_ENABLE_VMFUNC              0x2000
	#define CPU_BASED_CTL2_ENABLE_XSAVE_XRSTORS       0x100000

	#define VMCS_GUEST_DEBUGCTL_HIGH 0x00002803
	#define VIRTUAL_PROCESSOR_ID     0x00000000

	#define BITS_PER_LONG (sizeof(unsigned long) * 8)
	#define ORDER_LONG    (sizeof(unsigned long) == 4 ? 5 : 6)

	#define BITMAP_ENTRY(_nr, _bmap) ((_bmap))[(_nr) / BITS_PER_LONG]
	#define BITMAP_SHIFT(_nr)        ((_nr) % BITS_PER_LONG)

	/**
     * @brief Stack Size
     *
     */
	#define VMM_STACK_SIZE 0x8000

	/**
     * @brief Alignment Size
     *
     */
	#define ALIGNMENT_PAGE_SIZE 4096

	/**
     * @brief VMCS Region Size
     *
     */
	#define VMCS_SIZE 4096

	/**
     * @brief VMXON Region Size
     *
     */
	#define VMXON_SIZE 4096

	/**
	 * @brief PIN-Based Execution
	 *
	 */
	#define PIN_BASED_VM_EXECUTION_CONTROLS_EXTERNAL_INTERRUPT        0x00000001
	#define PIN_BASED_VM_EXECUTION_CONTROLS_NMI_EXITING               0x00000008
	#define PIN_BASED_VM_EXECUTION_CONTROLS_VIRTUAL_NMI               0x00000020
	#define PIN_BASED_VM_EXECUTION_CONTROLS_ACTIVE_VMX_TIMER          0x00000040
	#define PIN_BASED_VM_EXECUTION_CONTROLS_PROCESS_POSTED_INTERRUPTS 0x00000080

	/**
	 * @brief Pending External Interrups Buffer Capacity
	 *
	 */
	#define PENDING_INTERRUPTS_BUFFER_CAPACITY 64

	/**
	 * @brief CPUID Registers
	 *
	 */
	typedef struct _CPUID
	{
		int eax;
		int ebx;
		int ecx;
		int edx;
	} CPUID, * PCPUID;
	
	/**
     * @brief Things to consider when applying resour
     *
     */
	typedef enum _PROTECTED_HV_RESOURCES_PASSING_OVERS
	{
		//
		// for exception bitmap
		//
		PASSING_OVER_NONE = 0,
		PASSING_OVER_UD_EXCEPTIONS_FOR_SYSCALL_SYSRET_HOOK = 1,
		PASSING_OVER_EXCEPTION_EVENTS,

		//
		// for external interupts-exitings
		//
		PASSING_OVER_INTERRUPT_EVENTS,

		//
		// for external rdtsc/p exitings
		//
		PASSING_OVER_TSC_EVENTS,

		//
		// for external mov to hardware debug registers exitings
		//
		PASSING_OVER_MOV_TO_HW_DEBUG_REGS_EVENTS,

	} PROTECTED_HV_RESOURCES_PASSING_OVERS;

	/**
	 * @brief Temporary $context used in some EPT hook commands
	 *
	 */
	typedef struct _EPT_HOOKS_TEMPORARY_CONTEXT
	{
		UINT64 PhysicalAddress;
		UINT64 VirtualAddress;
	} EPT_HOOKS_TEMPORARY_CONTEXT, * PEPT_HOOKS_TEMPORARY_CONTEXT;

	/**
	 * Control Features in Intel 64 Processor.
	 *
	 * @remarks If any one enumeration condition for defined bit field holds.
	 */
	#define IA32_FEATURE_CONTROL                                         0x0000003A
	typedef union
	{
		struct
		{
		  /**
		   * @brief Lock bit <b>(R/WO)</b>
		   *
		   * [Bit 0] When set, locks this MSR from being written; writes to this bit will result in GP(0).
		   *
		   * @note Once the Lock bit is set, the contents of this register cannot be modified. Therefore the lock bit must be set
		   *       after configuring support for Intel Virtualization Technology and prior to transferring control to an option ROM or the
		   *       OS. Hence, once the Lock bit is set, the entire IA32_FEATURE_CONTROL contents are preserved across RESET when PWRGOOD is
		   *       not deasserted.
		   * @remarks If any one enumeration condition for defined bit field position greater than bit 0 holds.
		   */
			UINT64 LockBit : 1;
			#define IA32_FEATURE_CONTROL_LOCK_BIT_BIT                            0
			#define IA32_FEATURE_CONTROL_LOCK_BIT_FLAG                           0x01
			#define IA32_FEATURE_CONTROL_LOCK_BIT_MASK                           0x01
			#define IA32_FEATURE_CONTROL_LOCK_BIT(_)                             (((_) >> 0) & 0x01)

				/**
				 * @brief Enable VMX inside SMX operation <b>(R/WL)</b>
				 *
				 * [Bit 1] This bit enables a system executive to use VMX in conjunction with SMX to support Intel(R) Trusted Execution
				 * Technology. BIOS must set this bit only when the CPUID function 1 returns VMX feature flag and SMX feature flag set (ECX
				 * bits 5 and 6 respectively).
				 *
				 * @remarks If CPUID.01H:ECX[5] = 1 && CPUID.01H:ECX[6] = 1
				 */
			UINT64 EnableVmxInsideSmx : 1;
			#define IA32_FEATURE_CONTROL_ENABLE_VMX_INSIDE_SMX_BIT               1
			#define IA32_FEATURE_CONTROL_ENABLE_VMX_INSIDE_SMX_FLAG              0x02
			#define IA32_FEATURE_CONTROL_ENABLE_VMX_INSIDE_SMX_MASK              0x01
			#define IA32_FEATURE_CONTROL_ENABLE_VMX_INSIDE_SMX(_)                (((_) >> 1) & 0x01)

				/**
				 * @brief Enable VMX outside SMX operation <b>(R/WL)</b>
				 *
				 * [Bit 2] This bit enables VMX for a system executive that does not require SMX. BIOS must set this bit only when the
				 * CPUID function 1 returns the VMX feature flag set (ECX bit 5).
				 *
				 * @remarks If CPUID.01H:ECX[5] = 1
				 */
			UINT64 EnableVmxOutsideSmx : 1;
			#define IA32_FEATURE_CONTROL_ENABLE_VMX_OUTSIDE_SMX_BIT              2
			#define IA32_FEATURE_CONTROL_ENABLE_VMX_OUTSIDE_SMX_FLAG             0x04
			#define IA32_FEATURE_CONTROL_ENABLE_VMX_OUTSIDE_SMX_MASK             0x01
			#define IA32_FEATURE_CONTROL_ENABLE_VMX_OUTSIDE_SMX(_)               (((_) >> 2) & 0x01)
			UINT64 Reserved1 : 5;

			/**
			 * @brief SENTER Local Function Enable <b>(R/WL)</b>
			 *
			 * [Bits 14:8] When set, each bit in the field represents an enable control for a corresponding SENTER function. This field
			 * is supported only if CPUID.1:ECX.[bit 6] is set.
			 *
			 * @remarks If CPUID.01H:ECX[6] = 1
			 */
			UINT64 SenterLocalFunctionEnables : 7;
			#define IA32_FEATURE_CONTROL_SENTER_LOCAL_FUNCTION_ENABLES_BIT       8
			#define IA32_FEATURE_CONTROL_SENTER_LOCAL_FUNCTION_ENABLES_FLAG      0x7F00
			#define IA32_FEATURE_CONTROL_SENTER_LOCAL_FUNCTION_ENABLES_MASK      0x7F
			#define IA32_FEATURE_CONTROL_SENTER_LOCAL_FUNCTION_ENABLES(_)        (((_) >> 8) & 0x7F)

				/**
				 * @brief SENTER Global Enable <b>(R/WL)</b>
				 *
				 * [Bit 15] This bit must be set to enable SENTER leaf functions. This bit is supported only if CPUID.1:ECX.[bit 6] is set.
				 *
				 * @remarks If CPUID.01H:ECX[6] = 1
				 */
			UINT64 SenterGlobalEnable : 1;
			#define IA32_FEATURE_CONTROL_SENTER_GLOBAL_ENABLE_BIT                15
			#define IA32_FEATURE_CONTROL_SENTER_GLOBAL_ENABLE_FLAG               0x8000
			#define IA32_FEATURE_CONTROL_SENTER_GLOBAL_ENABLE_MASK               0x01
			#define IA32_FEATURE_CONTROL_SENTER_GLOBAL_ENABLE(_)                 (((_) >> 15) & 0x01)
			UINT64 Reserved2 : 1;

			/**
			 * @brief SGX Launch Control Enable <b>(R/WL)</b>
			 *
			 * [Bit 17] This bit must be set to enable runtime reconfiguration of SGX Launch Control via the IA32_SGXLEPUBKEYHASHn MSR.
			 *
			 * @remarks If CPUID.(EAX=07H, ECX=0H): ECX[30] = 1
			 */
			UINT64 SgxLaunchControlEnable : 1;
			#define IA32_FEATURE_CONTROL_SGX_LAUNCH_CONTROL_ENABLE_BIT           17
			#define IA32_FEATURE_CONTROL_SGX_LAUNCH_CONTROL_ENABLE_FLAG          0x20000
			#define IA32_FEATURE_CONTROL_SGX_LAUNCH_CONTROL_ENABLE_MASK          0x01
			#define IA32_FEATURE_CONTROL_SGX_LAUNCH_CONTROL_ENABLE(_)            (((_) >> 17) & 0x01)

				/**
				 * @brief SGX Global Enable <b>(R/WL)</b>
				 *
				 * [Bit 18] This bit must be set to enable SGX leaf functions.
				 *
				 * @remarks If CPUID.(EAX=07H, ECX=0H): EBX[2] = 1
				 */
			UINT64 SgxGlobalEnable : 1;
			#define IA32_FEATURE_CONTROL_SGX_GLOBAL_ENABLE_BIT                   18
			#define IA32_FEATURE_CONTROL_SGX_GLOBAL_ENABLE_FLAG                  0x40000
			#define IA32_FEATURE_CONTROL_SGX_GLOBAL_ENABLE_MASK                  0x01
			#define IA32_FEATURE_CONTROL_SGX_GLOBAL_ENABLE(_)                    (((_) >> 18) & 0x01)
			UINT64 Reserved3 : 1;

			/**
			 * @brief LMCE On <b>(R/WL)</b>
			 *
			 * [Bit 20] When set, system software can program the MSRs associated with LMCE to configure delivery of some machine check
			 * exceptions to a single logical processor.
			 *
			 * @remarks If IA32_MCG_CAP[27] = 1
			 */
			UINT64 LmceOn : 1;
			#define IA32_FEATURE_CONTROL_LMCE_ON_BIT                             20
			#define IA32_FEATURE_CONTROL_LMCE_ON_FLAG                            0x100000
			#define IA32_FEATURE_CONTROL_LMCE_ON_MASK                            0x01
			#define IA32_FEATURE_CONTROL_LMCE_ON(_)                              (((_) >> 20) & 0x01)
			UINT64 Reserved4 : 43;
		};

		UINT64 Flags;
	} IA32_FEATURE_CONTROL_REGISTER;

	/**
	 * @brief MTRR Range Descriptor
	 *
	 */
	typedef struct _MTRR_RANGE_DESCRIPTOR
	{
		SIZE_T PhysicalBaseAddress;
		SIZE_T PhysicalEndAddress;
		UCHAR  MemoryType;
	} MTRR_RANGE_DESCRIPTOR, * PMTRR_RANGE_DESCRIPTOR;

	typedef EPT_PML4 EPT_PML4_POINTER, * PEPT_PML4_POINTER;
	typedef EPDPTE   EPT_PML3_POINTER, * PEPT_PML3_POINTER;
	typedef EPDE_2MB EPT_PML2_ENTRY, * PEPT_PML2_ENTRY;
	typedef EPDE     EPT_PML2_POINTER, * PEPT_PML2_POINTER;
	typedef EPTE     EPT_PML1_ENTRY, * PEPT_PML1_ENTRY;

	/**
	* @brief Structure for saving EPT Table
	*
	*/
	typedef struct _VMM_EPT_PAGE_TABLE
	{
		/**
		 * @brief 28.2.2 Describes 512 contiguous 512GB memory regions each with 512 1GB regions.
		 */
		DECLSPEC_ALIGN(PAGE_SIZE)
			EPT_PML4_POINTER PML4[VMM_EPT_PML4E_COUNT];

			/**
			 * @brief Describes exactly 512 contiguous 1GB memory regions within a our singular 512GB PML4 region.
			 */
		DECLSPEC_ALIGN(PAGE_SIZE)
			EPT_PML3_POINTER PML3[VMM_EPT_PML3E_COUNT];

			/**
			 * @brief For each 1GB PML3 entry, create 512 2MB entries to map identity.
			 * NOTE: We are using 2MB pages as the smallest paging size in our map, so we do not manage individiual 4096 byte pages.
			 * Therefore, we do not allocate any PML1 (4096 byte) paging structures.
			 */
		DECLSPEC_ALIGN(PAGE_SIZE)
			EPT_PML2_ENTRY PML2[VMM_EPT_PML3E_COUNT][VMM_EPT_PML2E_COUNT];

	} VMM_EPT_PAGE_TABLE, * PVMM_EPT_PAGE_TABLE;

	/**
	 * @brief Structure to save the state of each hooked pages
	 *
	 */
	typedef struct _EPT_HOOKED_PAGE_DETAIL
	{
		DECLSPEC_ALIGN(PAGE_SIZE)
			CHAR FakePageContents[PAGE_SIZE];

			/**
			 * @brief Linked list entires for each page hook.
			 */
		LIST_ENTRY PageHookList;

		/**
		* @brief The virtual address from the caller prespective view (cr3)
		*/
		UINT64 VirtualAddress;

		/**
		* @brief The virtual address of it's enty on g_EptHook2sDetourListHead
		* this way we can de-allocate the list whenever the hook is finished
		*/
		UINT64 AddressOfEptHook2sDetourListEntry;

		/**
		 * @brief The base address of the page. Used to find this structure in the list of page hooks
		 * when a hook is hit.
		 */
		SIZE_T PhysicalBaseAddress;

		/**
		* @brief The base address of the page with fake contents. Used to swap page with fake contents
		* when a hook is hit.
		*/
		SIZE_T PhysicalBaseAddressOfFakePageContents;

		/*
		 * @brief The page entry in the page tables that this page is targetting.
		 */
		PEPT_PML1_ENTRY EntryAddress;

		/**
		 * @brief The original page entry. Will be copied back when the hook is removed
		 * from the page.
		 */
		EPT_PML1_ENTRY OriginalEntry;

		/**
		 * @brief The original page entry. Will be copied back when the hook is remove from the page.
		 */
		EPT_PML1_ENTRY ChangedEntry;

		/**
		* @brief The buffer of the trampoline function which is used in the inline hook.
		*/
		PCHAR Trampoline;

		/**
		 * @brief This field shows whether the hook contains a hidden hook for execution or not
		 */
		BOOLEAN IsExecutionHook;

		/**
		 * @brief If TRUE shows that this is the information about
		 * a hidden breakpoint command (not a monitor or hidden detours)
		 */
		BOOLEAN IsHiddenBreakpoint;

		/**
		 * @brief Address of hooked pages (multiple breakpoints on a single page)
		 * this is only used in hidden breakpoints (not hidden detours)
		 */
		UINT64 BreakpointAddresses[MaximumHiddenBreakpointsOnPage];

		/**
		 * @brief Character that was previously used in BreakpointAddresses
		 * this is only used in hidden breakpoints (not hidden detours)
		 */
		CHAR PreviousBytesOnBreakpointAddresses[MaximumHiddenBreakpointsOnPage];

		/**
		 * @brief Count of breakpoints (multiple breakpoints on a single page)
		 * this is only used in hidden breakpoints (not hidden detours)
		 */
		UINT64 CountOfBreakpoints;

	} EPT_HOOKED_PAGE_DETAIL, * PEPT_HOOKED_PAGE_DETAIL;

	 /**
	   * @brief Main structure for saving the state of EPT among the project
	   *
	   */
	#define EPT_MTRR_RANGE_DESCRIPTOR_MAX 0x9
	typedef struct _EPT_STATE
	{
		std::unordered_map<std::uint64_t, EPT_HOOKED_PAGE_DETAIL*>* HookedPagesList;                             // A list of the details about hooked pages
		MTRR_RANGE_DESCRIPTOR MemoryRanges[EPT_MTRR_RANGE_DESCRIPTOR_MAX]; // Physical memory ranges described by the BIOS in the MTRRs. Used to build the EPT identity mapping.
		ULONG                 NumberOfEnabledMemoryRanges;                 // Number of memory ranges specified in MemoryRanges
		EPT_POINTER           EptPointer;                                  // Extended-Page-Table Pointer
		PVMM_EPT_PAGE_TABLE   EptPageTable;                                // Page table entries for EPT operation

		PVMM_EPT_PAGE_TABLE SecondaryEptPageTable; // Secondary Page table entries for EPT operation (Used in debugger mechanisms)

	} EPT_STATE, * PEPT_STATE;

	/**
	 * @brief Types of actions for NMI broadcasting
	 *
	 */
	typedef enum _NMI_BROADCAST_ACTION_TYPE
	{
		NMI_BROADCAST_ACTION_NONE = 0,
		NMI_BROADCAST_ACTION_TEST,
		NMI_BROADCAST_ACTION_KD_HALT_CORE,

	} NMI_BROADCAST_ACTION_TYPE;

	/**
	 * @brief Use to modify Msrs or read MSR values
	 *
	 */
	typedef struct _PROCESSOR_DEBUGGING_MSR_READ_OR_WRITE
	{
		UINT64 Msr;   // Msr (ecx)
		UINT64 Value; // the value to write on msr

	} PROCESSOR_DEBUGGING_MSR_READ_OR_WRITE, * PPROCESSOR_DEBUGGING_MSR_READ_OR_WRITE;

	/**
	 * @brief The structure of storing breakpoints
	 *
	 */
	typedef struct _DEBUGGEE_BP_DESCRIPTOR
	{
		UINT64     BreakpointId;
		LIST_ENTRY BreakpointsList;
		BOOLEAN    Enabled;
		UINT64     Address;
		UINT64     PhysAddress;
		UINT32     Pid;
		UINT32     Tid;
		UINT32     Core;
		UINT16     InstructionLength;
		BYTE       PreviousByte;
		BOOLEAN    SetRflagsIFBitOnMtf;
		BOOLEAN    AvoidReApplyBreakpoint;

	} DEBUGGEE_BP_DESCRIPTOR, * PDEBUGGEE_BP_DESCRIPTOR;

	/**
	 * @brief Use to trace the execution in the case of instrumentation step-in
	 * command (i command)
	 *
	 */
	typedef struct _DEBUGGEE_INSTRUMENTATION_STEP_IN_TRACE
	{
		BOOLEAN WaitForInstrumentationStepInMtf;
		UINT16  CsSel; // the cs value to trace the execution modes

	} DEBUGGEE_INSTRUMENTATION_STEP_IN_TRACE, * PDEBUGGEE_INSTRUMENTATION_STEP_IN_TRACE;

	/**
	 * @brief Structure to save the state of adding trace for threads
	 * and processes
	 *
	 */
	typedef struct _DEBUGGEE_PROCESS_OR_THREAD_TRACING_DETAILS
	{
		BOOLEAN InitialSetProcessChangeEvent;
		BOOLEAN InitialSetThreadChangeEvent;

		BOOLEAN InitialSetByClockInterrupt;

		//
		// For threads
		//
		UINT64  CurrentThreadLocationOnGs;
		BOOLEAN DebugRegisterInterceptionState;
		BOOLEAN InterceptClockInterruptsForThreadChange;

		//
		// For processes
		//
		BOOLEAN IsWatingForMovCr3VmExits;
		BOOLEAN InterceptClockInterruptsForProcessChange;

	} DEBUGGEE_PROCESS_OR_THREAD_TRACING_DETAILS, * PDEBUGGEE_PROCESS_OR_THREAD_TRACING_DETAILS;

	/**
	 * @brief Saves the debugger state
	 * @details Each logical processor contains one of this structure which describes about the
	 * state of debuggers, flags, etc.
	 *
	 */
	typedef struct _PROCESSOR_DEBUGGING_STATE
	{
		volatile LONG                              Lock;
		volatile BOOLEAN                           WaitingToBeLocked;
		volatile BOOLEAN                           MainDebuggingCore;
		volatile BOOLEAN                           NmiCalledInVmxRootRelatedToHaltDebuggee;
		volatile NMI_BROADCAST_ACTION_TYPE         NmiBroadcastAction;
		BOOLEAN                                    IgnoreOneMtf;
		BOOLEAN                                    WaitForStepTrap;
		PROCESSOR_DEBUGGING_MSR_READ_OR_WRITE      MsrState;
		PDEBUGGEE_BP_DESCRIPTOR                    SoftwareBreakpointState;
		DEBUGGEE_INSTRUMENTATION_STEP_IN_TRACE     InstrumentationStepInTrace;
		BOOLEAN                                    EnableExternalInterruptsOnContinue;
		BOOLEAN                                    EnableExternalInterruptsOnContinueMtf;
		BOOLEAN                                    DisableTrapFlagOnContinue;
		BOOLEAN                                    DoNotNmiNotifyOtherCoresByThisCore;
		DEBUGGEE_PROCESS_OR_THREAD_TRACING_DETAILS ThreadOrProcessTracingDetails;
		BOOLEAN                                    BreakStarterCore;
		UINT16                                     InstructionLengthHint;
		UINT64                                     HardwareDebugRegisterForStepping;
		UINT64* ScriptEngineCoreSpecificLocalVariable;
		UINT64* ScriptEngineCoreSpecificTempVariable;

	} PROCESSOR_DEBUGGING_STATE, PPROCESSOR_DEBUGGING_STATE;

	/**
	 * @brief Save the state of core in the case of VMXOFF
	 *
	 */
	typedef struct _VMX_VMXOFF_STATE
	{
		BOOLEAN IsVmxoffExecuted; // Shows whether the VMXOFF executed or not
		UINT64  GuestRip;         // Rip address of guest to return
		UINT64  GuestRsp;         // Rsp address of guest to return

	} VMX_VMXOFF_STATE, * PVMX_VMXOFF_STATE;

	/**
	 * @brief The status of transparency of each core after and before VMX
	 *
	 */
	typedef struct _VM_EXIT_TRANSPARENCY
	{
		UINT64 PreviousTimeStampCounter;

		HANDLE  ThreadId;
		UINT64  RevealedTimeStampCounterByRdtsc;
		BOOLEAN CpuidAfterRdtscDetected;

	} VM_EXIT_TRANSPARENCY, * PVM_EXIT_TRANSPARENCY;

	/**
	 * @brief Memory mapper PTE and reserved virtual address
	 *
	 */
	typedef struct _MEMORY_MAPPER_ADDRESSES
	{
		UINT64 PteVirtualAddress; // The virtual address of PTE
		UINT64 VirualAddress;     // The actual kernel virtual address to read or write
	} MEMORY_MAPPER_ADDRESSES, * PMEMORY_MAPPER_ADDRESSES;

	/**
	 * @brief The status of each core after and before VMX
	 *
	 */
	typedef struct _VIRTUAL_MACHINE_STATE
	{
		BOOLEAN IsOnVmxRootMode;                                               // Detects whether the current logical core is on Executing on VMX Root Mode
		BOOLEAN IncrementRip;                                                  // Checks whether it has to redo the previous instruction or not (it used mainly in Ept routines)
		BOOLEAN HasLaunched;                                                   // Indicate whether the core is virtualized or not
		BOOLEAN IgnoreMtfUnset;                                                // Indicate whether the core should ignore unsetting the MTF or not
		BOOLEAN WaitForImmediateVmexit;                                        // Whether the current core is waiting for an immediate vm-exit or not
		PKDPC   KdDpcObject;                                                   // DPC object to be used in kernel debugger
		UINT64  LastVmexitRip;                                                 // RIP in the current VM-exit
		UINT64  VmxonRegionPhysicalAddress;                                    // Vmxon region physical address
		UINT64  VmxonRegionVirtualAddress;                                     // VMXON region virtual address
		UINT64  VmcsRegionPhysicalAddress;                                     // VMCS region physical address
		UINT64  VmcsRegionVirtualAddress;                                      // VMCS region virtual address
		UINT64  VmmStack;                                                      // Stack for VMM in VM-Exit State
		UINT64  MsrBitmapVirtualAddress;                                       // Msr Bitmap Virtual Address
		UINT64  MsrBitmapPhysicalAddress;                                      // Msr Bitmap Physical Address
		UINT64  IoBitmapVirtualAddressA;                                       // I/O Bitmap Virtual Address (A)
		UINT64  IoBitmapPhysicalAddressA;                                      // I/O Bitmap Physical Address (A)
		UINT64  IoBitmapVirtualAddressB;                                       // I/O Bitmap Virtual Address (B)
		UINT64  IoBitmapPhysicalAddressB;                                      // I/O Bitmap Physical Address (B)
		UINT32  PendingExternalInterrupts[PENDING_INTERRUPTS_BUFFER_CAPACITY]; // This list holds a buffer for external-interrupts that are in pending state due to the external-interrupt
																			   // blocking and waits for interrupt-window exiting
																			   // From hvpp :
																			   // Pending interrupt queue (FIFO).
																			   // Make storage for up-to 64 pending interrupts.
																			   // In practice I haven't seen more than 2 pending interrupts.

		PROCESSOR_DEBUGGING_STATE DebuggingState;         // Holds the debugging state of the processor (used by HyperDbg to execute commands)
		VMX_VMXOFF_STATE          VmxoffState;            // Shows the vmxoff state of the guest
		VM_EXIT_TRANSPARENCY      TransparencyState;      // The state of the debugger in transparent-mode
		PEPT_HOOKED_PAGE_DETAIL   MtfEptHookRestorePoint; // It shows the detail of the hooked paged that should be restore in MTF vm-exit
		MEMORY_MAPPER_ADDRESSES   MemoryMapper;           // Memory mapper details for each core, contains PTE Virtual Address, Actual Kernel Virtual Address
	} VIRTUAL_MACHINE_STATE, * PVIRTUAL_MACHINE_STATE;

	typedef union _CR_FIXED
	{
		UINT64 Flags;

		struct
		{
			unsigned long Low;
			long          High;

		} Fields;

	} CR_FIXED, * PCR_FIXED;

	/**
	 * @brief Segment selector
	 *
	 */

	typedef struct _VMX_SEGMENT_SELECTOR
	{
		UINT16                    Selector;
		VMX_SEGMENT_ACCESS_RIGHTS Attributes;
		UINT32                    Limit;
		UINT64                    Base;
	} VMX_SEGMENT_SELECTOR, * PVMX_SEGMENT_SELECTOR;

	/**
     * @brief Segment selector registers in x86
     *
     */
	typedef enum _SEGMENT_REGISTERS
	{
		ES = 0,
		CS,
		SS,
		DS,
		FS,
		GS,
		LDTR,
		TR
	} SEGMENT_REGISTERS;

	/**
	 * @brief General MSR Structure
	 *
	 */
	typedef union _MSR
	{
		struct
		{
			ULONG Low;
			ULONG High;
		} Fields;

		UINT64 Flags;

	} MSR, * PMSR;

	typedef struct GUEST_REGS
	{
		UINT64 rax; // 0x00
		UINT64 rcx; // 0x08
		UINT64 rdx; // 0x10
		UINT64 rbx; // 0x18
		UINT64 rsp; // 0x20
		UINT64 rbp; // 0x28
		UINT64 rsi; // 0x30
		UINT64 rdi; // 0x38
		UINT64 r8;  // 0x40
		UINT64 r9;  // 0x48
		UINT64 r10; // 0x50
		UINT64 r11; // 0x58
		UINT64 r12; // 0x60
		UINT64 r13; // 0x68
		UINT64 r14; // 0x70
		UINT64 r15; // 0x78
	} GUEST_REGS, * PGUEST_REGS;

	extern EPT_STATE* ept_state;
	extern VIRTUAL_MACHINE_STATE* guest_state;

	bool check_hypervisor_support() noexcept;
	bool initialize_hypervisor() noexcept;

	bool clear_vmcs_state(VIRTUAL_MACHINE_STATE* current_guest_state);

	extern PEPT_PML1_ENTRY get_pml1_entry(PVMM_EPT_PAGE_TABLE ept_page_table, std::size_t physical_address) noexcept;
	extern void ept_set_pml1_and_invalidate_tlb(PEPT_PML1_ENTRY entry_address, EPT_PML1_ENTRY entry_value, INVEPT_TYPE invalidation_type) noexcept;

	extern "C" bool virtualize_current_system(void* guest_stack) noexcept;
	extern "C" bool vmx_vmexit_handler(PGUEST_REGS guest_regs) noexcept;
	extern "C" std::uint64_t vmx_return_stack_pointer_for_vmxoff() noexcept;
	extern "C" std::uint64_t vmx_return_instruction_pointer_for_vmxoff() noexcept;
	extern "C" void vmx_vmresume() noexcept;
}