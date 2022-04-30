#pragma once
#include <ntifs.h>
#include <ntimage.h>
#include <ntstrsafe.h>
#include <string>
#include "process.hpp"
#include "extern.hpp"
#include "compatibility.hpp"
#include "module_map.hpp"

namespace module {
	NTSTATUS inject_dll(PEPROCESS process) noexcept;
	void* get_user_module(PEPROCESS process, const UNICODE_STRING& module_name, bool is_wow64) noexcept;
	void* get_module_export(void* module, const char* name_ordinal, PEPROCESS process, const UNICODE_STRING& name) noexcept;

}