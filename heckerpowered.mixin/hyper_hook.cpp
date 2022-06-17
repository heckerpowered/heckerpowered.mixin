#include "pch.hpp"

namespace hook::hyper
{
	void hook(void* victim, void* target [[maybe_unused]]) noexcept
	{
		virtualization::EPT_HOOKED_PAGE_DETAIL* hook_page = 
			static_cast<decltype(hook_page)>(memory::allocate<POOL_FLAG_NON_PAGED>(sizeof(virtualization::EPT_HOOKED_PAGE_DETAIL)));

		hook_page->PhysicalBaseAddress = MmGetPhysicalAddress(victim).QuadPart;

		auto target_page{ virtualization::get_pml1_entry(virtualization::ept_state->EptPageTable, hook_page->PhysicalBaseAddress) };

		virtualization::EPT_PML1_ENTRY changed_entry = *target_page;
		
		hook_page->VirtualAddress = reinterpret_cast<std::uint64_t>(victim);
		hook_page->EntryAddress = target_page;
		hook_page->OriginalEntry = *target_page;
		hook_page->PhysicalBaseAddressOfFakePageContents = static_cast<std::size_t>(MmGetPhysicalAddress(&hook_page->FakePageContents[0]).QuadPart / PAGE_SIZE);
		hook_page->IsExecutionHook = true;
		hook_page->BreakpointAddresses[0] = reinterpret_cast<std::uint64_t>(victim);
		hook_page->CountOfBreakpoints = 1;
		changed_entry.ReadAccess = 1;
		changed_entry.WriteAccess = 0;
		changed_entry.ExecuteAccess = 1;
		changed_entry.PageFrameNumber = hook_page->PhysicalBaseAddressOfFakePageContents;
		hook_page->ChangedEntry = changed_entry;

		virtualization::ept_state->HookedPagesList->emplace(hook_page->PhysicalBaseAddress, hook_page);

		if (virtualization::guest_state[KeGetCurrentProcessorIndex()].HasLaunched)
		{
			virtualization::ept_set_pml1_and_invalidate_tlb(target_page, changed_entry, INVEPT_TYPE::InveptSingleContext);
		}
		else
		{
			target_page->Flags = changed_entry.Flags;
		}
	}
}