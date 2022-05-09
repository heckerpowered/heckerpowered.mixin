#include "thread.hpp"

namespace thread
{
	NTSTATUS open_thread_by_id(void* thread_id, void*& handle, unsigned int access_mask) noexcept
	{
		PETHREAD thread;
		auto status = PsLookupThreadByThreadId(thread_id, &thread);
		if (!NT_SUCCESS(status)) return status;

		status = ObOpenObjectByPointer(thread, 0, nullptr, access_mask, *PsThreadType, MODE::KernelMode, &handle);
		ObDereferenceObject(thread);
		return status;
	}

	NTSTATUS open_thread(PETHREAD thread, void*& handle, unsigned int access_mask, unsigned int attributes, KPROCESSOR_MODE mode) noexcept
	{

		// If the Object parameter points to a file object(that is, a FILE_OBJECT structure), ObOpenObjectByPointer can only
		// be called after at least one handle has been created for the file object. Callers can check the Flags member of the
		// FILE_OBJECT structure that the Object parameter points to. If the FO_HANDLE_CREATED flag is set, this means that
		// one or more handles have been created for the file object, so it is safe to call ObOpenObjectByPointer.
		//
		// Any handle obtained by calling ObOpenObjectByPointer must eventually be released by calling ZwClose.
		// 
		// Driver routines that run in a process context other than that of the system process must set the
		// OBJ_KERNEL_HANDLE flag in the HandleAttributes parameter. This restricts the use of the handle returned by
		// ObOpenObjectByPointer to processes running in kernel mode. Otherwise, the handle can be accessed by the
		// process in whose context the driver is running.
		return ObOpenObjectByPointer(thread, attributes, nullptr, access_mask, *PsThreadType, mode, &handle);
	}

	NTSTATUS create_user_thread_by_handle(void* process, user_thread_routine start_address, void* argument, bool create_suspended,
		void*& thread, CLIENT_ID& client_id) noexcept
	{
		using RtlCreateUserThread = NTSTATUS(__stdcall*)(HANDLE, PSECURITY_DESCRIPTOR, BOOLEAN, ULONG, PULONG, PULONG, PVOID, PVOID, PHANDLE, PCLIENT_ID);

		static auto create_user_thread = static_cast<RtlCreateUserThread>(proc::get_kernel_procedure(L"RtlCreateUserThread"));
		if (create_user_thread)
			return create_user_thread(process, nullptr, create_suspended, 0, nullptr, nullptr, start_address, argument, &thread, &client_id);

		return STATUS_NOT_IMPLEMENTED;
	}

	NTSTATUS create_system_thread_by_handle(void* process, PKSTART_ROUTINE start_address, void* argument, void*& thread, CLIENT_ID& client_id) noexcept
	{

		// Use the InitializeObjectAttributes macro to initialize the members of the OBJECT_ATTRIBUTES structure.Note that
		// InitializeObjectAttributes initializes the SecurityQualityOfService member to NULL. If you must specify a non-
		// NULL value, set the SecurityQualityOfService member after initialization.
		//
		// To apply the attributes contained in this structure to an object or object handle, pass a pointer to this structure to
		// a routine that accesses objects or returns object handles, such as ZwCreateFile or ZwCreateDirectoryObject.
		//
		// All members of this structure are read-only. If a member of this structure is a pointer, the object that this member
		// points to is read-only as well. Read-only members and objects can be used to acquire relevant information but
		// must not be modified. To set the members of this structure, use the InitializeObjectAttributes macro.
		//
		// Driver routines that run in a process context other than that of the system process must set the
		// OBJ_KERNEL_HANDLE flag for the Attributes member (by using the InitializeObjectAttributes macro). This
		// restricts the use of a handle opened for that object to processes running only in kernel mode. Otherwise, the
		// handle can be accessed by the process in whose context the driver is running.
		// 
		// Attributes:
		// - OBJ_INHERIT
		// 	This handle can be inherited by child processes of the current process.
		// 
		// - OBJ_PERMANENT
		//  This flag only applies to objects that are named within the object manager. By
		//  default, such objects are deleted when all open handles to them are closed. If this
		//  flag is specified, the object is not deleted when all open handles are closed.
		//  Drivers can use the ZwMakeTemporaryObject routine to make a permanent
		//  object non-permanent.
		// - OBJ_EXCLUSIVE
		//  If this flag is set and the OBJECT_ATTRIBUTES structure is passed to a routine that
		//  creates an object, the object can be accessed exclusively. That is, once a process
		//  opens such a handle to the object, no other processes can open handles to this
		//  object.
		// 
		//  If this flag is set and the OBJECT_ATTRIBUTES structure is passed to a routine that
		//  creates an object handle, the caller is requesting exclusive access to the object for
		//  the process context that the handle was created in. This request can be granted
		//  only if the OBJ_EXCLUSIVE flag was set when the object was created.
		//
		// - OBJ_CASE_INSENSITIVE
		//  If this flag is specified, a case-insensitive comparison is used when matching the
		//  name pointed to by the ObjectName member against the names of existing
		//  objects. Otherwise, object names are compared using the default system settings.
		//
		// - OBJ_OPENIF
		//  If this flag is specified, by using the object handle, to a routine that creates
		//  objects and if that object already exists, the routine should open that object.
		//  Otherwise, the routine creating the object returns an NTSTATUS code of
		//  STATUS_OBJECT_NAME_COLLISION.
		// - OBJ_OPENLINK
		//  If an object handle, with this flag set, is passed to a routine that opens objects
		//  and if the object is a symbolic link object, the routine should open the symbolic
		//  link object itself, rather than the object that the symbolic link refers to (which is
		//  the default behavior).
		//
		// - OBJ_KERNEL_HANDLE
		//  The handle is created in system process context and can only be accessed from
		//  kernel mode.
		// 
		// - OBJ_FORCE_ACCESS_CHECK
		//  The routine that opens the handle should enforce all access checks for the object,
		//  even if the handle is being opened in kernel mode.
		//
		// - OBJ_DONT_REPARSE
		//  If this flag is set, no reparse points will be followed when parsing the name of the
		//  associated object. If any reparses are encountered the attempt will fail and return
		//  an STATUS_REPARSE_POINT_ENCOUNTERED result. This can be used to
		//  determine if there are any reparse points in the object's path, in security
		//  scenarios.
		//
		// - OBJ_IGNORE_IMPERSONATED_DEVICEMAP
		//  A device map is a mapping between DOS device names and devices in the
		//  system, and is used when resolving DOS names. Separate device maps exists for
		//  each user in the system, and users can manage their own device maps. Typically
		//  during impersonation, the impersonated user's device map would be used.
		//	However, when this flag is set, the process user's device map is used instead.
		//
		// - OBJ_VALID_ATTRIBUTES
		//  Reserved.
		OBJECT_ATTRIBUTES object_attributes{};

		// InitializeObjectAttributes initializes an OBJECT_ATTRIBUTES structure that specifies the properties of an object
		// handle to be opened. The caller can then pass a pointer to this structure to a routine that actually opens the
		// handle.
		//
		// Driver routines that run in a process context other than that of the system process must set the
		// OBJ_KERNEL_HANDLE flag for the Attributes parameter. This flag restricts the use of a handle opened for that
		// object to processes running only in kernel mode. Otherwise, the handle can be accessed by the process in whose
		// context the driver is running.
		//
		// Note that InitializeObjectAttributes always sets the SecurityQualityOfService member of OBJECT_ATTRIBUTES to
		// NULL. Drivers that require a non-NULL value can set SecurityQualityOfService directly.
		InitializeObjectAttributes(&object_attributes, nullptr, OBJ_KERNEL_HANDLE, nullptr, nullptr);

		// Drivers that create device-dedicated threads call this routine, either when they initialize or when I/O requests
		// begin to come in to such a driver's Dispatch routines. For example, a driver might create such a thread when it
		// receives an asynchronous device control request.
		//
		// PsCreateSystemThread creates a kernel-mode thread that begins a separate thread of execution within the
		// system. Such a system thread has no TEB or user-mode context and runs only in kernel mode.
		//
		// If the input ProcessHandle is NULL, the created thread is associated with the system process. Such a thread
		// continues running until either the system is shut down or the thread terminates itself by calling
		// PsTerminateSystemThread.
		//
		// Starting with Windows XP, driver routines that run in a process context other than that of the system process must
		// set the OBJ_KERNEL_HANDLE attribute for the ObjectAttributes parameter of PsCreateSystemThread. This restricts
		// the use of the handle returned by PsCreateSystemThread to processes running in kernel mode. Otherwise, the
		// thread handle can be accessed by the process in whose context the driver is running. Drivers can set the
		// OBJ_KERNEL_HANDLE attribute as follows.
		// 
		// - InitializeObjectAttributes(&ObjectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
		// 
		// Drivers for Windows 2000 and Windows 98/Me must call PsCreateSystemThread only from the system process context.
		// The newly created system thread runs at PASSIVE_LEVEL inside a critical region with normal kernel APCs disabled.
		return PsCreateSystemThread(&thread, GENERIC_ALL, &object_attributes, process, &client_id, start_address, argument);
	}

	NTSTATUS create_system_thread_by_id(void* process_id, PKSTART_ROUTINE start_address, void* argument, void*& thread, CLIENT_ID& client_id) noexcept
	{
		void* handle;
		auto status = process::open_process_by_id(process_id, handle);
		if (!NT_SUCCESS(status))
		{
			return status;
		}

		status = create_system_thread_by_handle(handle, start_address, argument, thread, client_id);
		ZwClose(handle);
		return status;
	}

	NTSTATUS create_system_thread(PKSTART_ROUTINE start_address, void* argument, void*& thread) noexcept
	{

		// Use the InitializeObjectAttributes macro to initialize the members of the OBJECT_ATTRIBUTES structure.Note that
		// InitializeObjectAttributes initializes the SecurityQualityOfService member to NULL. If you must specify a non-
		// NULL value, set the SecurityQualityOfService member after initialization.
		//
		// To apply the attributes contained in this structure to an object or object handle, pass a pointer to this structure to
		// a routine that accesses objects or returns object handles, such as ZwCreateFile or ZwCreateDirectoryObject.
		//
		// All members of this structure are read-only. If a member of this structure is a pointer, the object that this member
		// points to is read-only as well. Read-only members and objects can be used to acquire relevant information but
		// must not be modified. To set the members of this structure, use the InitializeObjectAttributes macro.
		//
		// Driver routines that run in a process context other than that of the system process must set the
		// OBJ_KERNEL_HANDLE flag for the Attributes member (by using the InitializeObjectAttributes macro). This
		// restricts the use of a handle opened for that object to processes running only in kernel mode. Otherwise, the
		// handle can be accessed by the process in whose context the driver is running.
		// 
		// Attributes:
		// - OBJ_INHERIT
		// 	This handle can be inherited by child processes of the current process.
		// 
		// - OBJ_PERMANENT
		//  This flag only applies to objects that are named within the object manager. By
		//  default, such objects are deleted when all open handles to them are closed. If this
		//  flag is specified, the object is not deleted when all open handles are closed.
		//  Drivers can use the ZwMakeTemporaryObject routine to make a permanent
		//  object non-permanent.
		// - OBJ_EXCLUSIVE
		//  If this flag is set and the OBJECT_ATTRIBUTES structure is passed to a routine that
		//  creates an object, the object can be accessed exclusively. That is, once a process
		//  opens such a handle to the object, no other processes can open handles to this
		//  object.
		// 
		//  If this flag is set and the OBJECT_ATTRIBUTES structure is passed to a routine that
		//  creates an object handle, the caller is requesting exclusive access to the object for
		//  the process context that the handle was created in. This request can be granted
		//  only if the OBJ_EXCLUSIVE flag was set when the object was created.
		//
		// - OBJ_CASE_INSENSITIVE
		//  If this flag is specified, a case-insensitive comparison is used when matching the
		//  name pointed to by the ObjectName member against the names of existing
		//  objects. Otherwise, object names are compared using the default system settings.
		//
		// - OBJ_OPENIF
		//  If this flag is specified, by using the object handle, to a routine that creates
		//  objects and if that object already exists, the routine should open that object.
		//  Otherwise, the routine creating the object returns an NTSTATUS code of
		//  STATUS_OBJECT_NAME_COLLISION.
		// - OBJ_OPENLINK
		//  If an object handle, with this flag set, is passed to a routine that opens objects
		//  and if the object is a symbolic link object, the routine should open the symbolic
		//  link object itself, rather than the object that the symbolic link refers to (which is
		//  the default behavior).
		//
		// - OBJ_KERNEL_HANDLE
		//  The handle is created in system process context and can only be accessed from
		//  kernel mode.
		// 
		// - OBJ_FORCE_ACCESS_CHECK
		//  The routine that opens the handle should enforce all access checks for the object,
		//  even if the handle is being opened in kernel mode.
		//
		// - OBJ_DONT_REPARSE
		//  If this flag is set, no reparse points will be followed when parsing the name of the
		//  associated object. If any reparses are encountered the attempt will fail and return
		//  an STATUS_REPARSE_POINT_ENCOUNTERED result. This can be used to
		//  determine if there are any reparse points in the object's path, in security
		//  scenarios.
		//
		// - OBJ_IGNORE_IMPERSONATED_DEVICEMAP
		//  A device map is a mapping between DOS device names and devices in the
		//  system, and is used when resolving DOS names. Separate device maps exists for
		//  each user in the system, and users can manage their own device maps. Typically
		//  during impersonation, the impersonated user's device map would be used.
		//	However, when this flag is set, the process user's device map is used instead.
		//
		// - OBJ_VALID_ATTRIBUTES
		//  Reserved.
		OBJECT_ATTRIBUTES object_attributes{};

		// InitializeObjectAttributes initializes an OBJECT_ATTRIBUTES structure that specifies the properties of an object
		// handle to be opened. The caller can then pass a pointer to this structure to a routine that actually opens the
		// handle.
		//
		// Driver routines that run in a process context other than that of the system process must set the
		// OBJ_KERNEL_HANDLE flag for the Attributes parameter. This flag restricts the use of a handle opened for that
		// object to processes running only in kernel mode. Otherwise, the handle can be accessed by the process in whose
		// context the driver is running.
		//
		// Note that InitializeObjectAttributes always sets the SecurityQualityOfService member of OBJECT_ATTRIBUTES to
		// NULL. Drivers that require a non-NULL value can set SecurityQualityOfService directly.
		InitializeObjectAttributes(&object_attributes, nullptr, OBJ_KERNEL_HANDLE, nullptr, nullptr);

		// Drivers that create device-dedicated threads call this routine, either when they initialize or when I/O requests
		// begin to come in to such a driver's Dispatch routines. For example, a driver might create such a thread when it
		// receives an asynchronous device control request.
		//
		// PsCreateSystemThread creates a kernel-mode thread that begins a separate thread of execution within the
		// system. Such a system thread has no TEB or user-mode context and runs only in kernel mode.
		//
		// If the input ProcessHandle is NULL, the created thread is associated with the system process. Such a thread
		// continues running until either the system is shut down or the thread terminates itself by calling
		// PsTerminateSystemThread.
		//
		// Starting with Windows XP, driver routines that run in a process context other than that of the system process must
		// set the OBJ_KERNEL_HANDLE attribute for the ObjectAttributes parameter of PsCreateSystemThread. This restricts
		// the use of the handle returned by PsCreateSystemThread to processes running in kernel mode. Otherwise, the
		// thread handle can be accessed by the process in whose context the driver is running. Drivers can set the
		// OBJ_KERNEL_HANDLE attribute as follows.
		// 
		// - InitializeObjectAttributes(&ObjectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
		// 
		// Drivers for Windows 2000 and Windows 98/Me must call PsCreateSystemThread only from the system process context.
		// The newly created system thread runs at PASSIVE_LEVEL inside a critical region with normal kernel APCs disabled.
		return PsCreateSystemThread(&thread, GENERIC_ALL, &object_attributes, nullptr, nullptr, start_address, argument);
	}

	PEPROCESS thread_to_process(PETHREAD thread) noexcept
	{
		return IoThreadToProcess(thread);
	};

	NTSTATUS queue_user_apc(PETHREAD thread, void* user_function, void* arg1, void* arg2, void* arg3, bool force) noexcept
	{
		auto inject_apc{ reinterpret_cast<PKAPC>(memory::allocate(sizeof(KAPC))) };
		if (inject_apc == nullptr) return STATUS_INSUFFICIENT_RESOURCES;

		KeInitializeApc(inject_apc, thread, KAPC_ENVIRONMENT::OriginalApcEnvironment, [](PKAPC apc, PKNORMAL_ROUTINE*, void** context, void**, void**)
		{
			if (PsIsThreadTerminating(PsGetCurrentThread()))
				*context = nullptr;

			// Fix Wow64 APC
			if (PsGetCurrentProcessWow64Process() != NULL)
				PsWrapApcWow64Thread(context, reinterpret_cast<void**>(context));

			memory::free(apc);
		}, nullptr, static_cast<PKNORMAL_ROUTINE>(user_function), MODE::UserMode, arg1);

		PKAPC prepare_apc{};
		if (force)
		{
			prepare_apc = reinterpret_cast<PKAPC>(memory::allocate(sizeof(KAPC)));
			KeInitializeApc(prepare_apc, thread, KAPC_ENVIRONMENT::OriginalApcEnvironment, [](PKAPC apc, PKNORMAL_ROUTINE*, void**, void**, void**)
			{
				KeTestAlertThread(MODE::UserMode);
				memory::free(apc);
			}, nullptr, nullptr, MODE::KernelMode, nullptr);
		}

		if (KeInsertQueueApc(inject_apc, arg2, arg3, 0))
		{
			if (force && prepare_apc) KeInsertQueueApc(prepare_apc, nullptr, nullptr, 0);

			return STATUS_SUCCESS;
		}
		else
		{
			memory::free(inject_apc);
			if (prepare_apc) memory::free(prepare_apc);

			return STATUS_NOT_CAPABLE;
		}
	}
}