#pragma once
#include <intrin.h>

#define MSR_IA32_FEATURE_CONTROL 		0x03a
#define MSR_IA32_VMX_BASIC              0x480
#define MSR_IA32_VMX_PINBASED_CTLS		0x481
#define MSR_IA32_VMX_PROCBASED_CTLS		0x482
#define MSR_IA32_VMX_EXIT_CTLS          0x483
#define MSR_IA32_VMX_ENTRY_CTLS         0x484
#define MSR_IA32_VMX_PROCBASED_CTLS2    0x48b

#define MSR_IA32_SYSENTER_CS            0x174
#define MSR_IA32_SYSENTER_ESP           0x175
#define MSR_IA32_SYSENTER_EIP           0x176
#define MSR_IA32_DEBUGCTL               0x1d9

namespace virtualization
{
	inline bool bios_support_virtualization() noexcept
	{
		return (__readmsr(MSR_IA32_FEATURE_CONTROL) & 0x5) == 0x5;
	}

	inline bool cpu_support_virtualization() noexcept
	{
		int cpu_id[4]{};
		__cpuidex(cpu_id, 1, 0);
		return (cpu_id[2] >> 5) & 1;
	}

	inline bool enabled_virtualization() noexcept
	{
		return (__readcr4() >> 13) & 1;
	}

	inline bool virtualization_available() noexcept
	{
		return bios_support_virtualization() && cpu_support_virtualization() && enabled_virtualization();
	}
}