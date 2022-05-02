#include "object_callback.hpp"

namespace callback {
	std::vector<void*> callbacks;

	NTSTATUS register_callback(POBJECT_TYPE* type, POB_PRE_OPERATION_CALLBACK pre, POB_POST_OPERATION_CALLBACK post,
		OB_OPERATION operation_type) noexcept
	{
		// This structure is used by the ObRegisterCallbacks routine. The CallBackRegistration parameter to this routine is a
		// pointer to a buffer that contains an OB_CALLBACK_REGISTRATION structure that is followed by an array of one or
		// more OB_OPERATION_REGISTRATION structures.
		// 
		// In each OB_OPERATION_REGISTRATION structure passed to ObRegisterCallback, the caller must supply one or
		// both callback routines. If the PreOperation and PostOperation members of this structure are both NULL, the
		// callback registration operation fails.
		OB_OPERATION_REGISTRATION operation{};
		operation.ObjectType = type;
		operation.Operations = operation_type;
		operation.PreOperation = pre;
		operation.PostOperation = post;

		// This structure is used by the ObRegisterCallbacks routine. The CallBackRegistration parameter to this routine is a
		// pointer to a buffer that contains an OB_CALLBACK_REGISTRATION structure that is followed by an array of one or
		// more OB_OPERATION_REGISTRATION structures.
		OB_CALLBACK_REGISTRATION registration{};
		registration.Version = OB_FLT_REGISTRATION_VERSION;
		registration.RegistrationContext = nullptr;
		registration.OperationRegistrationCount = 1;

		// The altitude is an infinite-precision string interpreted as a decimal number. 
		// A filter driver that has a low numerical altitude is loaded into the I/O 
		// stack below a filter driver that has a higher numerical value.
		RtlInitUnicodeString(&registration.Altitude, L"0");
		registration.OperationRegistration = &operation;

		void* registration_handle;

		// WinXp unsupported: For the WinXP support we should import "ObRegisterCallbacks"
		// and "ObUnRegisterCallbacks" dynamically
		// Available starting with Windows Vista with Service Pack 1 (SP1) and Windows Server 2008.
		auto status{ ObRegisterCallbacks(&registration, &registration_handle) };
		if (NT_SUCCESS(status)) { callbacks.push_back(registration_handle); }

		return status;
	}

	void unregister_callbacks() noexcept {
		for (auto&& handle : callbacks) {

			// Do not call ObRegisterCallbacks more than once. This is a "double free" and results in Bug Check 0x7E:
			// SYSTEM_THREAD_EXCEPTION_NOT_HANDLED.
			ObUnRegisterCallbacks(handle);
		}
	}

	NTSTATUS initialize_callbacks() noexcept
	{
		NTSTATUS status = register_callback(PsProcessType, [](auto registration_context [[maybe_unused]], auto operation_information) {
			if (guard::guarded(PsGetProcessId(static_cast<PEPROCESS>(operation_information->Object)))) { 
				zero_handle_access(operation_information);
			}

			return OB_PREOP_CALLBACK_STATUS::OB_PREOP_SUCCESS;
		});
		if (!NT_SUCCESS(status)) { return status; }

		status = register_callback(PsThreadType, [](auto registration_content [[maybe_unused]], auto operation_information) {
			if(guard::guarded(PsGetProcessId(thread::thread_to_process(static_cast<PETHREAD>(operation_information->Object))))){
				zero_handle_access(operation_information);
			}
			
			return OB_PREOP_CALLBACK_STATUS::OB_PREOP_SUCCESS;
		});
		if (!NT_SUCCESS(status)) { return status; }

		return status;
	}

	inline void zero_handle_access(POB_PRE_OPERATION_INFORMATION operation_information) noexcept {
		operation_information->Parameters->CreateHandleInformation.DesiredAccess =
			operation_information->Parameters->CreateHandleInformation.OriginalDesiredAccess =
			operation_information->Parameters->DuplicateHandleInformation.DesiredAccess =
			operation_information->Parameters->DuplicateHandleInformation.OriginalDesiredAccess = 0;
	}
}