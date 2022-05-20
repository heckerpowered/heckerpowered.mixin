#include "pch.hpp"

namespace callback {
	namespace image {
		std::vector<PLOAD_IMAGE_NOTIFY_ROUTINE> registered_callbacks;

		NTSTATUS register_callbacks(PLOAD_IMAGE_NOTIFY_ROUTINE routine) noexcept {
			const auto status{ PsSetLoadImageNotifyRoutine(routine) };
			if (NT_SUCCESS(status)) { registered_callbacks.emplace_back(routine); }

			return status;
		}

		NTSTATUS unregister_callbacks() noexcept {
			NTSTATUS status{ STATUS_SUCCESS };
			for (auto&& callback : registered_callbacks) { status |= PsRemoveLoadImageNotifyRoutine(callback); }

			return status;
		}
	}
}