#pragma once
#include <ntifs.h>

namespace file {
    NTSTATUS get_file_name(const UNICODE_STRING& path, UNICODE_STRING& name) noexcept;
    NTSTATUS get_directory_name(const UNICODE_STRING& path, UNICODE_STRING& name) noexcept;
    NTSTATUS exists(const UNICODE_STRING& path) noexcept;
}