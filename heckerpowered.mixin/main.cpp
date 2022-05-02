#include "main.hpp"

extern "C" NTSTATUS DriverEntry(struct _DRIVER_OBJECT* driver_object, PUNICODE_STRING registery_path [[maybe_unused]] )
{
	NTSTATUS status{ STATUS_SUCCESS };

	mixin::driver_object = driver_object;

	status = compatibility::initialize_dynamic_data();
	if (!NT_SUCCESS(status)) return status;

	status = hook::initialize();
	if (!NT_SUCCESS(status)) return status;

	guard::initialize();

	static UNICODE_STRING device_name RTL_CONSTANT_STRING(L"\\Device\\Mixin");
	static UNICODE_STRING symbolic_link_name RTL_CONSTANT_STRING(L"\\??\\Mixin");

	PDEVICE_OBJECT device;

	// IoCreateDevice creates a device object and returns a pointer to the object. The caller is responsible for deleting
	// the object when it is no longer needed by calling IoDeleteDevice.
	//
	// IoCreateDevice can only be used to create an unnamed device object, or a named device object for which a
	// security descriptor is set by an INF file. Otherwise, drivers must use IoCreateDeviceSecure to create named device
	// objects. For more information, see Creating a Device Object. The caller is responsible for setting certain members
	// of the returned device object. For more information, see Initializing a Device Object and the device-type-specific
	// documentation for your device.
	//
	// Be careful to specify the DeviceType and DeviceCharacteristics values in the correct parameters. Both parameters
	// use system-defined FILE_XXX constants and some driver writers specify the values in the wrong parameters by
	// mistake.
	//
	// A remote file system that creates a named device object for a network redirector, and that registers using
	// FsRtlRegisterUncProvider, must specify FILE_REMOTE_DEVICE as one of the options in the DeviceCharacteristics
	// parameter of IoCreateDevice.
	//
	// Device objects for disks, tapes, CD-ROMs, and RAM disks are given a Volume Parameter Block (VPB) that is
	// initialized to indicate that the volume has never been mounted on the device.
	//
	// If a driver's call to IoCreateDevice returns an error, the driver should release any resources that it allocated for
	// that device.
	status = IoCreateDevice(driver_object, 0, &device_name, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, false, &device);
	if (!NT_SUCCESS(status)) return status;

	driver_object->DriverUnload = [](auto driver_object)
	{
		callback::unregister_callbacks();
		callback::process::unregister_callbacks();
		callback::image::unregister_callbacks();
		IoDeleteSymbolicLink(&symbolic_link_name);

		// When handling a PnP IRP_MN_REMOVE_DEVICE request, a PnP driver calls IoDeleteDevice to delete any
		// associated device objects. See Handling an IRP_MN_REMOVE_DEVICE Request for details.
		//
		// A legacy driver should call this routine when it is being unloaded or when its DriverEntry routine encounters a
		// fatal initialization error, such as being unable to properly initialize a physical device. This routine also is called
		// when a driver reconfigures its devices dynamically. For example, a disk driver called to repartition a disk would call
		// IoDeleteDevice to tear down the device objects representing partitions to be replaced.
		//
		// A driver must release certain resources for which the driver supplied storage in its device extension before it calls
		// IoDeleteDevice. For example, if the driver stores the pointer to its interrupt object(s) in the device extension, it
		// must call IoDisconnectInterrupt before calling IoDeleteDevice.
		//
		// A driver can call IoDeleteDevice only once for a given device object.
		//
		// When a driver calls IoDeleteDevice, the I/O manager deletes the target device object if there are no outstanding
		// references to it. However, if any outstanding references remain, the I/O manager marks the device object as
		// "delete pending" and deletes the device object when the references are released.
		auto device = driver_object->DeviceObject;
		if (device) IoDeleteDevice(device);

		k_hook::stop();
	};

	// The _Dispatch_type_ annotations does not seem to be detected on Lambda expressions
	#pragma warning(disable: __WARNING_DISPATCH_MISSING)

	// A driver's DispatchCreate routine should be named XxxDispatchCreate, where Xxx is a
	// driver-specific prefix. The driver's DriverEntry routine must store the DispatchCreate
	// routine's address in DriverObject->MajorFunction[IRP_MJ_CREATE].
	//
	// A driver's DispatchClose routine should be named XxxDispatchClose, where Xxx is a
	// driver-specific prefix. The driver's DriverEntry routine must store the DispatchClose
	// routine's address in DriverObject->MajorFunction[IRP_MJ_CLOSE].
	driver_object->MajorFunction[IRP_MJ_CREATE] =
		driver_object->MajorFunction[IRP_MJ_CLOSE] = [](auto device_object [[maybe_unused]], auto irp)
	{
		irp->IoStatus.Status = STATUS_SUCCESS;
		irp->IoStatus.Information = 0;

		// When a driver has finished all processing for a given IRP, it calls IoCompleteRequest. The I/O manager checks the
		// IRP to determine whether any higher-level drivers have set up an IoCompletion routine for the IRP. If so, each
		// IoCompletion routine is called, in turn, until every layered driver in the chain has completed the IRP.
		//
		// When all drivers have completed a given IRP, the I/O manager returns status to the original requester of the
		// operation. Note that a higher-level driver that sets up a driver-created IRP must supply an IoCompletion routine to
		// release the IRP it created.
		// 
		// Never call IoCompleteRequest while holding a spin lock. Attempting to complete an IRP while holding a spin lock
		// can cause deadlocks.
		IoCompleteRequest(irp, IO_NO_INCREMENT);
		return STATUS_SUCCESS;
	};

	// A driver receives this I/O control code because user-mode thread has called the Microsoft Win32 DeviceIoControl
	// function, or a higher-level kernel-mode driver has set up the request. Possibly, a user-mode driver has called
	// DeviceIoControl, passing in a driver-defined (also called private) I/O control code, to request device- or driver-
	// specific support from a closely coupled, kernel-mode device driver.
	//
	// On receipt of a device I/O control request, a higher-level driver usually passes the IRP on to the next-lower driver.
	// However, there are some exceptions to this practice. For example, a class driver that has stored configuration
	// information obtained from the underlying port driver might complete certain IOCTL_XXX requests without passing
	// the IRP down to the corresponding port driver.
	//
	// On receipt of a device I/O control request, a device driver examines the I/O control code to determine how to
	// satisfy the request. For most public I/O control codes, device drivers transfer a small amount of data to or from
	// the buffer at Irp->AssociatedIrp.SystemBuffer.
	// 
	// A driver's DispatchDeviceControl routine should be named XxxDispatchDeviceControl,
	// where Xxx is a driver-specific prefix. The driver's DriverEntry routine must store the
	// DispatchDeviceControl routine's address in DriverObject-
	// >MajorFunction[IRP_MJ_DEVICE_CONTROL].
	//
	// The system uses the FILE_XXX flags in the I/O control code to determine whether the
	// IRP sender has the privileges to send the IRP to the device object. Drivers for Windows
	// Server 2003 and later versions of Windows can use the
	// IoValidateDeviceIoControlAccess routine to perform stricter access checks within
	// DispatchDeviceControl.
	driver_object->MajorFunction[IRP_MJ_DEVICE_CONTROL] = [](auto device_object [[maybe_unused]], auto irp)
	{

		// Every driver must call IoGetCurrentIrpStackLocation with each IRP it is sent in order to get any parameters for the
		// current request. Unless a driver supplies a dispatch routine for each IRP_MJ_XXX code that the driver handles, the
		// driver also must check its I/O stack location in the IRP to determine what operation is being requested.
		//
		// If a driver is passing the same parameters that it received to the next-lower driver, it should call
		// IoCopyCurrentIrpStackLocationToNext or IoSkipCurrentIrpStackLocation instead of getting a pointer to the next-
		// lower stack location and copying the parameters manually.
		auto stack_location = IoGetCurrentIrpStackLocation(irp);
		auto code = stack_location->Parameters.DeviceIoControl.IoControlCode;
		auto length = stack_location->Parameters.DeviceIoControl.InputBufferLength;
		auto method = com::extract_method(code);

		if (method == METHOD_BUFFERED)
		{

			// For this transfer type, IRPs supply a pointer to a buffer at Irp->AssociatedIrp.SystemBuffer. This buffer represents
			// both the input buffer and the output buffer that are specified in calls to DeviceIoControl and
			// IoBuildDeviceIoControlRequest. The driver transfers data out of, and then into, this buffer.
			// 
			// For input data, the buffer size is specified by Parameters.DeviceIoControl.InputBufferLength in the driver's
			// IO_STACK_LOCATION structure. For output data, the buffer size is specified by
			// Parameters.DeviceIoControl.OutputBufferLength in the driver's IO_STACK_LOCATION structure.
			// 
			// The size of the space that the system allocates for the single input/output buffer is the larger of the two length
			// values.
			auto system_buffer = irp->AssociatedIrp.SystemBuffer;
			irp->IoStatus.Status = com::handle_request(code, length, system_buffer, system_buffer);
		}
		else if (method == METHOD_IN_DIRECT || method == METHOD_OUT_DIRECT)
		{

			// For these transfer types, IRPs supply a pointer to a buffer at Irp->AssociatedIrp.SystemBuffer. This represents the
			// first buffer that is specified in calls to DeviceIoControl and IoBuildDeviceIoControlRequest. The buffer size is
			// specified by Parameters.DeviceIoControl.InputBufferLength in the driver's IO_STACK_LOCATION structure.
			// 
			// For these transfer types, IRPs also supply a pointer to an MDL at Irp->MdlAddress. This represents the second
			// buffer that is specified in calls to DeviceIoControl and IoBuildDeviceIoControlRequest. This buffer can be used as
			// either an input buffer or an output buffer, as follows:
			// 
			// - METHOD_IN_DIRECT is specified if the driver that handles the IRP receives data in the buffer when it is called.
			// The MDL describes an input buffer, and specifying METHOD_IN_DIRECT ensures that the executing thread
			// has read-access to the buffer.
			//
			// - METHOD_OUT_DIRECT is specified if the driver that handles the IRP will write data into the buffer before
			// completing the IRP. The MDL describes an output buffer, and specifying METHOD_OUT_DIRECT ensures that
			// the executing thread has write-access to the buffer.
			// 
			// For both of these transfer types, Parameters.DeviceIoControl.OutputBufferLength specifies the size of the buffer
			// that is described by the MDL.
			auto input_buffer = irp->AssociatedIrp.SystemBuffer;
			auto out_buffer = irp->MdlAddress ? MmGetSystemAddressForMdlSafe(irp->MdlAddress, MM_PAGE_PRIORITY::NormalPagePriority 
				| MdlMappingNoExecute) : nullptr;
			irp->IoStatus.Status = com::handle_request(code, length, input_buffer, out_buffer);
		}
		else if (method == METHOD_NEITHER)
		{

			// The I/O manager does not provide any system buffers or MDLs. The IRP supplies the user-mode virtual addresses
			// of the input and output buffers that were specified to DeviceIoControl or IoBuildDeviceIoControlRequest,
			// without validating or mapping them.
			// 
			// The input buffer's address is supplied by Parameters.DeviceIoControl.Type3InputBuffer in the driver's
			// IO_STACK_LOCATION structure, and the output buffer's address is specified by Irp->UserBuffer.
			// 
			// Buffer sizes are supplied by Parameters.DeviceIoControl.InputBufferLength and
			// Parameters.DeviceIoControl.OutputBufferLength in the driver's IO_STACK_LOCATION structure.
			auto input_buffer = stack_location->Parameters.DeviceIoControl.Type3InputBuffer;
			auto out_buffer = irp->UserBuffer;
			irp->IoStatus.Status = com::handle_request(code, length, input_buffer, out_buffer);
		}
		else
		{
			irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
		}

		irp->IoStatus.Information = stack_location->Parameters.DeviceIoControl.OutputBufferLength;

		// When a driver has finished all processing for a given IRP, it calls IoCompleteRequest. The I/O manager checks the
		// IRP to determine whether any higher-level drivers have set up an IoCompletion routine for the IRP. If so, each
		// IoCompletion routine is called, in turn, until every layered driver in the chain has completed the IRP.
		//
		// When all drivers have completed a given IRP, the I/O manager returns status to the original requester of the
		// operation. Note that a higher-level driver that sets up a driver-created IRP must supply an IoCompletion routine to
		// release the IRP it created.
		// 
		// Never call IoCompleteRequest while holding a spin lock. Attempting to complete an IRP while holding a spin lock
		// can cause deadlocks.
		IoCompleteRequest(irp, IO_NO_INCREMENT);
		return irp->IoStatus.Status;
	};
	#pragma warning(default: __WARNING_DISPATCH_MISSING)

	// WDM drivers do not name device objectsand therefore should not use this routine.Instead, a WDM driver should
	// call IoRegisterDeviceInterface to set up a symbolic link.
	status = IoCreateSymbolicLink(&symbolic_link_name, &device_name);
	if (!NT_SUCCESS(status))
	{
		IoDeleteDevice(device);
		return status;
	}

	// Bypass the special certificate check otherwise the registration object callback will fail
	#pragma warning(disable: __WARNING_INACCESSIBLE_MEMBER)
	reinterpret_cast<PLDR_DATA_TABLE_ENTRY64>(driver_object->DriverSection)->Flags |= 0x20;
	#pragma warning(default: __WARNING_INACCESSIBLE_MEMBER)

	status = callback::initialize_callbacks();
	if (!NT_SUCCESS(status)) return status;

	status = callback::process::register_callbacks();
	if (!NT_SUCCESS(status)) return status;

	status = com::initialize_requests();
	if (!NT_SUCCESS(status)) return status;

	// DO_BUFFERED_IO or DO_DIRECT_IO
	// Specifies the type of buffering that is used by the I/O manager for I/O requests that are sent to the device stack.
	// Higher-level drivers OR this member with the same value as the next-lower driver in the stack, except possibly for
	// highest-level drivers.
	// 
	// DO_BUS_ENUMERATED_DEVICE
	// The operating system sets this flag in each physical device object (PDO). Drivers must not modify this flag.
	// 
	// DO_DEVICE_INITIALIZING
	// The I/O manager sets this flag when it creates the device object. A device function driver or filter driver clears the
	// flag in its AddDevice routine, after it does the following:
	// - Attaches the device object to the device stack.
	// - Establishes the device power state.
	// - Performs a bitwise OR operation on the member with one of the power flags (if it is necessary).
	// The Plug and Play (PnP) manager checks that the flag is clear after the AddDevice routine returns.
	// 
	// DO_EXCLUSIVE
	// Indicates that the driver services an exclusive device, such as a video, serial, parallel, or sound device. WDM drivers
	// must not set this flag. For more information, see the Specifying Exclusive Access to Device Objects topic.
	//
	// DO_MAP_IO_BUFFER
	// This flag is no longer used. Drivers should not set this flag.
	//
	// DO_POWER_INRUSH
	// Drivers of devices that require inrush current when the device is turned on must set this flag. A driver cannot set
	// both this flag and DO_POWER_PAGABLE.
	//
	// DO_POWER_PAGABLE
	// Pageable drivers that are compatible with Microsoft Windows 2000 and later versions of Windows, are not part of
	// the paging path, and do not require inrush current must set this flag. The system calls such drivers at IRQL =
	// PASSIVE_LEVEL. Drivers cannot set both this flag and DO_POWER_INRUSH. All drivers for WDM, Microsoft
	// Windows 98, and Windows Millennium Edition must set DO_POWER_PAGABLE.
	// 
	// DO_SHUTDOWN_REGISTERED
	// Used by the I/O manager to indicate that a driver has registered the device object for shutdown notifications. This
	// flag should not be used by drivers.
	//
	// DO_VERIFY_VOLUME
	// Removable-media drivers set this flag while they process transfer requests. Such drivers should also check for this
	// flag in the target for a transfer request before they transfer any data. For more information, see the Supporting
	// Removable Media topic.
	device->Flags |= DO_BUFFERED_IO;

	// When the filter device object is created, IoCreateDevice sets the DO_DEVICE_INITIALIZING flag on the device
	// object. After the filter is successfully attached, this flag must be cleared. Note that if this flag is not cleared, no
	// more filter drivers can attach to the filter chain because the call to IoAttachDeviceToDeviceStackSafe will fail.
	//
	// Note   It is not necessary to clear the DO_DEVICE_INITIALIZING flag on device objects that are created in
	// DriverEntry, because this is done automatically by the I/O Manager. However, your driver should clear this flag on
	// all other device objects that it creates.
	device->Flags &= ~DO_DEVICE_INITIALIZING;

	return status;
}

namespace mixin
{
	struct _DRIVER_OBJECT* driver_object;
}