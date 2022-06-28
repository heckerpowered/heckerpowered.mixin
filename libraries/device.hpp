#pragma once
#include <ntddk.h>

namespace sdk::device
{
	_IRQL_requires_max_(PASSIVE_LEVEL)
	_Must_inspect_result_
	[[nodiscard]] inline NTSTATUS const initialize(struct _DRIVER_OBJECT* driver_object) noexcept
	{
		ASSERT(driver_object != nullptr);
		ASSERT(KeGetCurrentIrql() <= PASSIVE_LEVEL);

		if (KeGetCurrentIrql() > PASSIVE_LEVEL) [[unlikely]]
		{
			return IRQL_NOT_LESS_OR_EQUAL;
		}

		UNICODE_STRING device_name = RTL_CONSTANT_STRING(L"\\Device\\Mixin");
		PDEVICE_OBJECT device{};

		//
		// Free it later
		//
#pragma warning(disable: __WARNING_MEMORY_LEAK)
		NTSTATUS status = IoCreateDevice(driver_object, 0, &device_name, FILE_DEVICE_UNKNOWN, 
			FILE_DEVICE_SECURE_OPEN, false, &device);
#pragma warning(default: __WARNING_MEMORY_LEAK)

		if (!NT_SUCCESS(status))
		{
			return status;
		}

		UNICODE_STRING symbolic_link_name = RTL_CONSTANT_STRING(L"\\??\\Mixin");
		status = IoCreateSymbolicLink(&symbolic_link_name, &device_name);
		if (!NT_SUCCESS(status)) [[unlikely]]
		{
			return status;
		}

		return status;
	}

	_IRQL_requires_max_(PASSIVE_LEVEL)
	_Must_inspect_result_
	[[nodiscard]] inline NTSTATUS const finalize(PDEVICE_OBJECT device_object) noexcept
	{
		ASSERT(device_object != nullptr);
		ASSERT(KeGetCurrentIrql() <= PASSIVE_LEVEL);

		if (KeGetCurrentIrql() > PASSIVE_LEVEL) [[unlikely]]
		{
			return IRQL_NOT_LESS_OR_EQUAL;
		}

		UNICODE_STRING symbolic_link_name = RTL_CONSTANT_STRING(L"\\??\\Mixin");
		NTSTATUS const status = IoDeleteSymbolicLink(&symbolic_link_name);
		if (!NT_SUCCESS(status)) [[unlikely]]
		{
			return status;
		}

		IoDeleteDevice(device_object);

		return status;
	}
}