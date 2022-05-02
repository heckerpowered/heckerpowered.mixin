#include "thread_callback.hpp"

namespace callback
{
	namespace thread
	{
		std::vector<PCREATE_THREAD_NOTIFY_ROUTINE> registered_callbacks;

		NTSTATUS register_callbacks(PCREATE_THREAD_NOTIFY_ROUTINE routine) noexcept
		{
			const auto status{ PsSetCreateThreadNotifyRoutine(routine) };
			if (NT_SUCCESS(status)) { registered_callbacks.emplace_back(routine); }

			return status;
		}

		NTSTATUS unregister_callbacks() noexcept
		{
			NTSTATUS status{ STATUS_SUCCESS };
			for (auto&& callback : registered_callbacks) { status |= PsRemoveCreateThreadNotifyRoutine(callback); }

			return status;
		}
	}
}