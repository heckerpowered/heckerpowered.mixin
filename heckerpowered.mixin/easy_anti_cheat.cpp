#include "easy_anti_cheat.hpp"

namespace cheat {
	namespace eac {
		void* eac_base;
		size_t eac_base_size;

		NTSTATUS initialize() noexcept {
			const auto status{ callback::image::register_callbacks([](PUNICODE_STRING FullImageName, HANDLE ProcessId [[maybe_unused]] ,PIMAGE_INFO ImageInfo) {
				if (MmIsAddressValid(FullImageName) && std::wstring(FullImageName->Buffer).find(L"EasyAntiCheat.sys") != std::wstring::npos) {
					eac_base = ImageInfo->ImageBase;
					eac_base_size = ImageInfo->ImageSize;
				}
			}) };

			if (NT_SUCCESS(status)) {
				auto pre{ reinterpret_cast<PLDR_DATA_TABLE_ENTRY64>(reinterpret_cast<PLDR_DATA_TABLE_ENTRY64>(mixin::driver_object)->InLoadOrderLinks.Flink) };
				auto next{ reinterpret_cast<PLDR_DATA_TABLE_ENTRY64>(pre->InLoadOrderLinks.Flink) };
				while (next != pre) {
					if (std::wstring(next->FullDllName.Buffer).find(L"EasyAntiCheat.sys") != std::wstring::npos) {
						eac_base = next->DllBase;
						eac_base_size = next->SizeOfImage;
						break;
					}

					next = reinterpret_cast<PLDR_DATA_TABLE_ENTRY64>(next->InLoadOrderLinks.Flink);
				}
			}

			return status;
		}
	}
}