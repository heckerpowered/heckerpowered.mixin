#pragma once
#include "memory.hpp"

namespace sys
{
	inline void shutdown() noexcept
	{

		// mov ax, 2001
		// mov dx, 1004
		// out dx, ax
		// ret
		
		// Use the out command to shut down the system, 
		// which in theory cannot be intercepted
		mem::execute<0x66, 0xB8, 0x01, 0x20, 0x66, 0xBA, 0x04, 0x10, 0x66, 0xEF, 0xC3>();
	}

	inline void reboot() noexcept
	{

		// mov al, -2
		// out 64, al
		// ret
		
		// Use the out command to reboot the system, which
		// in theory cannot be intercepted
		mem::execute<0xB0, 0xFE, 0xE6, 0x64, 0xC3>();
	}
}