#pragma once

namespace callback {
	NTSTATUS register_callback(POBJECT_TYPE * type, POB_PRE_OPERATION_CALLBACK pre, POB_POST_OPERATION_CALLBACK post = nullptr, OB_OPERATION operation_type =
		OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE) noexcept;
	void unregister_callbacks() noexcept;
	NTSTATUS initialize_callbacks() noexcept;
	void zero_handle_access(POB_PRE_OPERATION_INFORMATION information) noexcept;
}