#pragma once
#include <ntifs.h>
#include <ntimage.h>
#include "extern.hpp"

namespace ssdt {
	int get_ssdt_index(const char* ExportName);
}