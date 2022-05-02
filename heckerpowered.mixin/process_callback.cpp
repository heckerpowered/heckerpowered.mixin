#include "process_callback.hpp"

namespace callback {
	namespace process {
		void process_notify_routine(PEPROCESS process [[maybe_unused]], HANDLE process_id, 
			PPS_CREATE_NOTIFY_INFO create_info) noexcept {
			if (create_info == nullptr) { guard::disable_guard(process_id); }
		}

		NTSTATUS register_callbacks() noexcept {

			// Highest-level drivers can call PsSetCreateProcessNotifyRoutineEx to register a
			// PCREATE_PROCESS_NOTIFY_ROUTINE_EX routine. An installable file system (IFS) or highest-level system-profiling
			// driver might register a process-creation callback routine to track which processes are created and deleted against
			// the driver's internal state across the system.
			//
			// A driver must remove any callback routines that it registers before it unloads. You can remove the callback routine
			// by calling PsSetCreateProcessNotifyRoutineEx with Remove set to TRUE. A driver must not make this call from its
			// implementation of the PCREATE_PROCESS_NOTIFY_ROUTINE_EX callback routine.
			//
			// The operating system calls the driver's process-notify routine at PASSIVE_LEVEL inside a critical region with normal
			// kernel APCs disabled. When a process is created, the process-notify routine runs in the context of the thread that
			// created the new process. When a process is deleted, the process-notify routine runs in the context of the last
			// thread to exit from the process.
			return PsSetCreateProcessNotifyRoutineEx(process_notify_routine, false);
		}

		NTSTATUS unregister_callbacks() noexcept {

			// Highest-level drivers can call PsSetCreateProcessNotifyRoutineEx to register a
			// PCREATE_PROCESS_NOTIFY_ROUTINE_EX routine. An installable file system (IFS) or highest-level system-profiling
			// driver might register a process-creation callback routine to track which processes are created and deleted against
			// the driver's internal state across the system.
			//
			// A driver must remove any callback routines that it registers before it unloads. You can remove the callback routine
			// by calling PsSetCreateProcessNotifyRoutineEx with Remove set to TRUE. A driver must not make this call from its
			// implementation of the PCREATE_PROCESS_NOTIFY_ROUTINE_EX callback routine.
			//
			// The operating system calls the driver's process-notify routine at PASSIVE_LEVEL inside a critical region with normal
			// kernel APCs disabled. When a process is created, the process-notify routine runs in the context of the thread that
			// created the new process. When a process is deleted, the process-notify routine runs in the context of the last
			// thread to exit from the process.
			return PsSetCreateProcessNotifyRoutineEx(process_notify_routine, true);
		}
	}
}