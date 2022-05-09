#pragma once
#include "ia32.hpp"

namespace virtualization::assembly
{
	enum class vm_call
	{
		call_exit_vt,
		call_ept_hook,
		call_ept_unhook,
	};

	extern "C"
	{
		bool __fastcall vmx_launch(void* callBack, void* thisPoint);
		void __fastcall vmm_entry_point();
		void __fastcall _invd();
		void __fastcall vmx_call(unsigned __int64 num, unsigned __int64 param);
		unsigned char __fastcall __fastcall _invvpid(
			 unsigned __int64 invvpid_type,
			 unsigned __int64* invvpid_descriptor);
		void sgdt(void*);
		void __fastcall write_gdt(const Gdtr* gdtr);
		unsigned short __fastcall read_ldtr();
		void __fastcall write_tr( unsigned short task_register);
		unsigned short __fastcall read_tr();
		void __fastcall write_es( unsigned short segment_selector);
		unsigned short __fastcall read_es();
		void __fastcall write_cs( unsigned short segment_selector);
		unsigned short __fastcall read_cs();
		void __fastcall write_ss( unsigned short segment_selector);
		unsigned short __fastcall read_ss();
		void __fastcall write_ds( unsigned short segment_selector);
		unsigned short __fastcall read_ds();
		void __fastcall write_fs( unsigned short segment_selector);
		unsigned short __fastcall read_fs();
		void __fastcall write_gs( unsigned short segment_selector);
		unsigned short __fastcall read_gs();
		unsigned __int64 __fastcall load_access_rights_byte(unsigned __int64 segment_selector);
	}
}