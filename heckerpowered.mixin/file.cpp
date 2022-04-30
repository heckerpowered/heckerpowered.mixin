#include "file.hpp"

namespace file {
    NTSTATUS get_file_name(const UNICODE_STRING& path, UNICODE_STRING& name) noexcept {
        if (path.Length < 2)
        {
            name = path;
            return STATUS_NOT_FOUND;
        }

        for (unsigned short i(path.Length / static_cast<unsigned short>(sizeof(wchar_t) - 1)); i != 0; i--) {
            if (path.Buffer[i] == L'\\' || path.Buffer[i] == L'/') {
                name.Buffer = &path.Buffer[i + 1];
                name.Length = name.MaximumLength = path.Length - (i + 1) * static_cast<unsigned short>(sizeof(wchar_t));
                return STATUS_SUCCESS;
            }
        }

        name = path;
        return STATUS_NOT_FOUND;
    }

    NTSTATUS get_directory_name(const UNICODE_STRING& path, UNICODE_STRING& name) noexcept {
        if (path.Length < 2)
        {
            name = path;
            return STATUS_NOT_FOUND;
        }

        for (unsigned short i(path.Length / sizeof(wchar_t) - 1 ); i != 0; i--)
        {
            if (path.Buffer[i] == L'\\' || path.Buffer[i] == L'/')
            {
                name.Buffer = path.Buffer;
                name.Length = name.MaximumLength = i * sizeof(wchar_t);
                return STATUS_SUCCESS;
            }
        }
        
        name = path;
        return STATUS_NOT_FOUND;
    }

    NTSTATUS exists(const UNICODE_STRING& path) noexcept {
        OBJECT_ATTRIBUTES attributes{};
        InitializeObjectAttributes(&attributes, const_cast<PUNICODE_STRING>(&path), OBJ_KERNEL_HANDLE, nullptr, nullptr);

        HANDLE file;
        IO_STATUS_BLOCK status_block{};
        NTSTATUS status{ ZwCreateFile(&file, FILE_READ_DATA | SYNCHRONIZE, &attributes, &status_block, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ,
            FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, nullptr, 0) };

        if (NT_SUCCESS(status)) ZwClose(file);

        return status;
    }
}