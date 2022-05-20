#pragma once

namespace io
{
	template<typename...args_t>
	inline bool print(const args_t&...args) noexcept
	{
		return DbgPrintEx(DPFLTR_TYPE::DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, core::connect("[Mixins]: ", args...).data());
	}

	template<typename...args_t>
	inline bool println(const args_t&...args) noexcept
	{
		return DbgPrintEx(DPFLTR_TYPE::DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, core::connect("[Mixins]: ", args..., "\n").data());
	}
}