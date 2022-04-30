#include "process_callback.hpp"

namespace callback {
	namespace process {
		#ifdef FEATURE_PROCESS_CALLBACK
		std::deque<process_info> created_processes;
		std::vector<HANDLE> events;
		#endif

		void process_notify_routine(PEPROCESS process [[maybe_unused]], HANDLE process_id [[maybe_unused]], PPS_CREATE_NOTIFY_INFO create_info [[maybe_unused]] ) noexcept {
			if (create_info == nullptr) protect::end_protect(process_id);

			#ifdef FEATURE_ANTI_LAUNCH_ANTI_VIRUS
			constexpr std::string_view anti_launch = R"(wsctrlsvc.exe;HipsTray.exe;HipsDaemon.exe;QMUsbGuard.exe;QQPCLeakScan.exe;QQPCRealTimeSpeedup.exe;
		QQPCRTP.exe;QQPCTray.exe;QAXEntClient.exe;QAXrps.exe;QAXTray.exe)";
			if (anti_launch.find(PsGetProcessImageFileName(process)) != std::string_view::npos) {
				create_info->CreationStatus = STATUS_ACCESS_DENIED;
			}
			#endif

			#ifdef FEATURE_PROCESS_CALLBACK
			process_info info{};
			info.creating.process_id = create_info->CreatingThreadId.UniqueProcess;
			info.creating.thread_id = create_info->CreatingThreadId.UniqueThread;
			info.process_id = process_id;
			info.parent_process_id = create_info->ParentProcessId;

			created_processes.push_back(info);

			for (auto&& event : events) ZwSetEvent(event, nullptr);
			events.clear();
			#endif
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

		#ifdef FEATURE_PROCESS_CALLBACK
		NTSTATUS subscribe_event(HANDLE& event) noexcept {
			auto status = ZwCreateEvent(&event, EVENT_ALL_ACCESS, nullptr, EVENT_TYPE::NotificationEvent, false);
			if (!NT_SUCCESS(status)) return status;

			events.push_back(event);
			return status;
		}

		NTSTATUS wait_for_create() noexcept {
			HANDLE event{};
			auto status = subscribe_event(event);
			if (!NT_SUCCESS(status)) return status;

			status = ZwWaitForSingleObject(event, false, nullptr);
			ZwClose(event);
			return status;
		}
		#endif
	}
}