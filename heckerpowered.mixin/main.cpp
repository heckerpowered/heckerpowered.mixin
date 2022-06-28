#include "main.hpp"

_Use_decl_annotations_
extern "C" NTSTATUS DriverEntry(struct _DRIVER_OBJECT* driver_object, PUNICODE_STRING registery_path [[maybe_unused]] )
{
	PAGED_CODE();

	//
	// Sets the unload function so that the driver can be unloaded.
	//
	driver_object->DriverUnload = DriverUnload;

	driver_object->MajorFunction[IRP_MJ_CREATE] = DefaultDispatcher;
	driver_object->MajorFunction[IRP_MJ_CLOSE] = DefaultDispatcher;

	//
	// Initialize device and symbolic inorder to communicate with the usermode application.
	//
	NTSTATUS const status = sdk::device::initialize(driver_object);
	if (!NT_SUCCESS(status))
	{
		return status;
	}

	//
	// Bypass the special certificate check otherwise the registration object callback will fail
	//
#pragma warning(disable: __WARNING_INACCESSIBLE_MEMBER)
	static_cast<PLDR_DATA_TABLE_ENTRY64>(driver_object->DriverSection)->Flags |= 0x20;
#pragma warning(default: __WARNING_INACCESSIBLE_MEMBER)

	return STATUS_SUCCESS;
}

_Use_decl_annotations_
extern "C" void DriverUnload(struct _DRIVER_OBJECT* driver_object) {
	static_cast<void>(sdk::device::finalize(driver_object->DeviceObject));
}

_Use_decl_annotations_
NTSTATUS DefaultDispatcher(struct _DEVICE_OBJECT* device_object [[maybe_unused]], struct _IRP* irp) noexcept
{
	//
	// Set the Status field of the input IRP's I/O status block with an appropriate NTSTATUS, usually STATUS_SUCCESS.
	//
	irp->IoStatus.Status = STATUS_NOT_SUPPORTED;

	//
	// Set the Information field of the input IRP's I/O status block to zero.
	//
	irp->IoStatus.Information = 0;

	//
	// Call IoCompleteRequest with the IRP and a PriorityBoost of IO_NO_INCREMENT.
	//
	IoCompleteRequest(irp, IO_NO_INCREMENT);

	//
	// Return the NTSTATUS that it set in the Status field of the IRP's I/O status block.
	//
	return irp->IoStatus.Status;
}