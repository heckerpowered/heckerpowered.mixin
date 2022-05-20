#include "pch.hpp"

namespace ext {
	void* kernel_base;
	unsigned long kernel_base_size;
	PSYSTEM_SERVICE_DESCRIPTOR_TABLE ssdt;

	void* get_kernel_base(unsigned long& size) noexcept {
		if (kernel_base) {
			size = kernel_base_size;
			return kernel_base;
		}

		unsigned long bytes{};
		NTSTATUS status{ ZwQuerySystemInformation(SYSTEM_INFORMATION_CLASS::SystemModuleInformation, nullptr, bytes, &bytes) };
		if (bytes == 0) return nullptr;

		auto modules{ reinterpret_cast<PRTL_PROCESS_MODULES>(memory::allocate(bytes)) };
		status = ZwQuerySystemInformation(SYSTEM_INFORMATION_CLASS::SystemModuleInformation, modules, bytes, &bytes);

		if (!NT_SUCCESS(status)) {
			memory::free(modules);
			return nullptr;
		}

		auto module_information{ modules->Modules };
		auto check_pointer{ proc::get_kernel_procedure(L"NtOpenFile") };
		for (unsigned int i{}; i < modules->NumberOfModules; i++) {
			auto module{ module_information[i] };
			if (check_pointer >= module.ImageBase && check_pointer < static_cast<unsigned char*>(module.ImageBase) + module.ImageSize) {
				kernel_base = module.ImageBase;
				kernel_base_size = module.ImageSize;
				size = kernel_base_size;
				break;
			}
		}

		memory::free(modules);
		return kernel_base;
	}

	PSYSTEM_SERVICE_DESCRIPTOR_TABLE get_ssdt_base() noexcept {
		if (ssdt) return ssdt;

		auto ntos_base{ reinterpret_cast<unsigned char*>(get_kernel_base(kernel_base_size)) };
		if (ntos_base == nullptr) return nullptr;

		PIMAGE_NT_HEADERS nt_headers{ RtlImageNtHeader(ntos_base) };
		PIMAGE_SECTION_HEADER first_section{ reinterpret_cast<PIMAGE_SECTION_HEADER>(nt_headers + 1) };
		auto maxium{ first_section + nt_headers->FileHeader.NumberOfSections };
		for (auto section{ first_section }; section < maxium; section++) {

			// Non-paged, non-discardable, readable sections
			// Probably still not fool-proof enough...
			if (section->Characteristics & IMAGE_SCN_MEM_NOT_PAGED &&
				section->Characteristics & IMAGE_SCN_MEM_EXECUTE &&
				!(section->Characteristics & IMAGE_SCN_MEM_DISCARDABLE) &&
				(*reinterpret_cast<unsigned long*>(section->Name) != 'TINI') &&
				(*reinterpret_cast<unsigned long*>(section->Name) != 'EGAP'))
			{
				void* found{};

				// KiSystemServiceRepeat pattern
				const UCHAR pattern[] = "\x4c\x8d\x15\xcc\xcc\xcc\xcc\x4c\x8d\x1d\xcc\xcc\xcc\xcc\xf7";
				const NTSTATUS status = util::pattern_scan(pattern, 0xCC, sizeof(pattern) - 1, ntos_base + section->VirtualAddress, section->Misc.VirtualSize, found);
				if (NT_SUCCESS(status))
				{
					ssdt = reinterpret_cast<PSYSTEM_SERVICE_DESCRIPTOR_TABLE>(
						reinterpret_cast<unsigned char*>(found) + *reinterpret_cast<unsigned long*>(reinterpret_cast<unsigned char*>(found) + 3) + 7);
					return ssdt;
				}
			}
		}

		return nullptr;
	}

	void* get_ssdt_entry(unsigned long index) {
		unsigned long size{};
		void* base = get_kernel_base(size);
		auto ssdt_base{ get_ssdt_base() };
		if (ssdt_base == nullptr || base == nullptr) return nullptr;
		if (index > ssdt_base->NumberOfServices) return nullptr;

		return reinterpret_cast<unsigned char*>(ssdt_base->ServiceTableBase) + (reinterpret_cast<long*>(ssdt_base->ServiceTableBase)[index] >> 4);
	}

	extern "C" NTSTATUS
		NTAPI
		ZwCreateThreadEx(
			OUT PHANDLE hThread,
			IN ACCESS_MASK DesiredAccess,
			IN PVOID ObjectAttributes,
			IN HANDLE ProcessHandle,
			IN PVOID lpStartAddress,
			IN PVOID lpParameter,
			IN ULONG Flags,
			IN SIZE_T StackZeroBits,
			IN SIZE_T SizeOfStackCommit,
			IN SIZE_T SizeOfStackReserve,
			IN PNT_PROC_THREAD_ATTRIBUTE_LIST AttributeList
		)
	{
		typedef NTSTATUS(NTAPI* fnNtCreateThreadEx)
			(
				OUT PHANDLE hThread,
				IN ACCESS_MASK DesiredAccess,
				IN PVOID ObjectAttributes,
				IN HANDLE ProcessHandle,
				IN PVOID lpStartAddress,
				IN PVOID lpParameter,
				IN ULONG Flags,
				IN SIZE_T StackZeroBits,
				IN SIZE_T SizeOfStackCommit,
				IN SIZE_T SizeOfStackReserve,
				OUT PVOID lpBytesBuffer
				);

		NTSTATUS status = STATUS_SUCCESS;

		fnNtCreateThreadEx NtCreateThreadEx = (fnNtCreateThreadEx)(ULONG_PTR)get_ssdt_entry(compatibility::get_data().nt_create_thread_ex);
		if (NtCreateThreadEx)
		{
			//
			// If previous mode is UserMode, addresses passed into ZwCreateThreadEx must be in user-mode space
			// Switching to KernelMode allows usage of kernel-mode addresses
			//
			const auto mode{ util::set_previous_mode(MODE::KernelMode) };

			status = NtCreateThreadEx(
				hThread, DesiredAccess, ObjectAttributes,
				ProcessHandle, lpStartAddress, lpParameter,
				Flags, StackZeroBits, SizeOfStackCommit,
				SizeOfStackReserve, AttributeList
			);

			util::set_previous_mode(mode);
		}
		else
			status = STATUS_NOT_FOUND;

		return status;
	}

	void* get_kernel_base() noexcept {
		return get_kernel_base(kernel_base_size);
	}
}