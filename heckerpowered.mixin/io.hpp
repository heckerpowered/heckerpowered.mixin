#pragma once
#include <ntifs.h>

namespace io
{
	template<typename...Args>
	[[msvc::forceinline]]
	inline unsigned int print(const char* format, Args const*... args) noexcept
	{
		return DbgPrint(format, args...);
	}
}