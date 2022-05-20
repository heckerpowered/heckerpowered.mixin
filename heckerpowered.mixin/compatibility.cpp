#include "pch.hpp"

namespace compatibility {
	dynamic_data _data;

	NTSTATUS initialize_dynamic_data(dynamic_data& data) noexcept {
		RTL_OSVERSIONINFOEXW version{};
		version.dwOSVersionInfoSize = sizeof(version);
		const auto status = RtlGetVersion(reinterpret_cast<PRTL_OSVERSIONINFOW>(&version));
		if (!NT_SUCCESS(status)) return status;

		switch (data.version = static_cast<windows_version>((version.dwMajorVersion << 8) | (version.dwMinorVersion << 4) | version.wServicePackMajor)) {
			case windows_version::WINVER_7:
				data.debug_port = 0x1f0;
				data.object_table = 0x200;
				data.protection = 0x43C;// Bitfield, bit index - 0xB
				data.system_thread = 0; // Not exist
				data.thread_cross_flags = 0x448;
				data.nt_create_thread_ex = 0x0A5;
				break;
			case windows_version::WINVER_7_SP1:
				data.debug_port = 0x1f0;
				data.object_table = 0x200;
				data.protection = 0x43C;// Bitfield, bit index - 0xB
				data.system_thread = 0x4C;
				data.nt_create_thread_ex = 0x0A5;
				break;

			case windows_version::WINVER_8:
				data.debug_port = 0x410;
				data.object_table = 0x408;
				data.protection = 0x648;
				data.system_thread = 0x74;
				data.nt_create_thread_ex = 0x0AF;
				break;

			case windows_version::WINVER_81:
				data.debug_port = 0x410;
				data.object_table = 0x408;
				data.protection = 0x67A;
				data.system_thread = 0x74;
				data.nt_create_thread_ex = 0xB0;
				data.eprocess_flag2 = 0x2F8;
				break;

				// Windows 10, build 16299/15063/14393/10586
			case windows_version::WINVER_10:
				switch (version.dwBuildNumber) {
					case 10586:
						data.debug_port = 0x420;
						data.object_table = 0x418;
						data.protection = 0x6B2;
						data.system_thread = 0x74;
						data.nt_create_thread_ex = 0xB4;
						data.eprocess_flag2 = 0x300;
						break;

					case 14393:
						data.debug_port = 0x420;
						data.object_table = 0x418;
						data.protection = 0; // Unsupported
						data.system_thread = 0x74;
						data.nt_create_thread_ex = 0xB6;
						data.eprocess_flag2 = 0x300;
						break;

					case 15063:
						data.debug_port = 0x420;
						data.object_table = 0x418;
						data.protection = 0x6CA;
						data.system_thread = 0x74;
						data.nt_create_thread_ex = 0xB9;
						data.eprocess_flag2 = 0x300;
						break;

					case 16299:
						data.debug_port = 0x420;
						data.object_table = 0x418;
						data.protection = 0x6CA;
						data.system_thread = 0x74;
						data.nt_create_thread_ex = 0xBA;
						data.eprocess_flag2 = 0x828;
						break;

					case 17134:
						data.debug_port = 0x420;
						data.object_table = 0x418;
						data.protection = 0x6CA;
						data.system_thread = 0x74;
						data.nt_create_thread_ex = 0xBB;
						data.eprocess_flag2 = 0x828;
						break;

					case 17763:
						data.debug_port = 0x420;
						data.object_table = 0x418;
						data.protection = 0x6CA;
						data.system_thread = 0x74;
						data.nt_create_thread_ex = 0xBC;
						data.eprocess_flag2 = 0x820;
						break;

					case 18362:
					case 18363:
						data.debug_port = 0x420;
						data.object_table = 0x418;
						data.protection = 0x6FA;
						data.system_thread = 0x74;
						data.nt_create_thread_ex = 0xBD;
						data.eprocess_flag2 = 0x850;
						break;

					case 19041:
					case 19042:
					case 19043:
					case 19044:
						data.debug_port = 0x578;
						data.object_table = 0x570;
						data.protection = 0x87A;
						data.system_thread = 0x74;
						data.nt_create_thread_ex = 0xC1;
						data.eprocess_flag2 = 0x9D4;
						break;
					default:
						if (version.dwBuildNumber >= 22000 && version.dwBuildNumber <= 22483) {
							data.debug_port = 0x578;
							data.object_table = 0x570;
							data.protection = 0x87A;
							data.system_thread = 0x74;
						}

						data.system_thread = 0x74;
						data.nt_create_thread_ex = 0xC1;
						break;
				}
				break;
			default:
				break;
		}

		return status;
	}

	NTSTATUS initialize_dynamic_data() noexcept {
		return initialize_dynamic_data(_data);
	}

	NTSTATUS set_debug_port(PEPROCESS process, unsigned __int64 value) {
		if (_data.debug_port == 0) return STATUS_NOT_SUPPORTED;

		*reinterpret_cast<unsigned __int64*>(reinterpret_cast<unsigned __int64>(process) + _data.debug_port) = value;
		return STATUS_SUCCESS;
	}

	NTSTATUS set_system_thread(PETHREAD thread, bool is_system_thread) {
		bool success{};
		#define PS_CROSS_THREAD_FLAGS_SYSTEM 0x00000010UL
		if (_data.thread_cross_flags != 0) {
			if (is_system_thread) {
				*reinterpret_cast<ULONG*>(reinterpret_cast<unsigned __int64>(thread) + _data.thread_cross_flags) |= PS_CROSS_THREAD_FLAGS_SYSTEM;
				success = true;
			}
			else {
				*reinterpret_cast<ULONG*>(reinterpret_cast<unsigned __int64>(thread) + _data.thread_cross_flags) &= ~PS_CROSS_THREAD_FLAGS_SYSTEM;
				success = true;
			}
		}

		if (_data.system_thread != 0) {
			*reinterpret_cast<ULONG*>(reinterpret_cast<unsigned __int64>(thread) + _data.system_thread) = is_system_thread;
			success = true;
		}

		return success ? STATUS_SUCCESS : STATUS_NOT_IMPLEMENTED;
	}

	const dynamic_data& get_data() {
		return _data;
	}
}