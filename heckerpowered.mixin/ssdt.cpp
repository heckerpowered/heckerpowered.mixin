#include "ssdt.hpp"

namespace ssdt
{
	constexpr auto INVALID_PE_VALUE = static_cast<unsigned long>(-1);

	unsigned char* static_file_data = 0;
	ULONG static_file_size = 0;

	unsigned long rva_to_section(IMAGE_NT_HEADERS* header, unsigned long rva)
	{
		auto section_header{ IMAGE_FIRST_SECTION(header) };
		const auto sections{ header->FileHeader.NumberOfSections };
		for (unsigned short i{}; i < sections; i++)
			if (section_header[i].VirtualAddress <= rva && (section_header[i].VirtualAddress + section_header[i].Misc.VirtualSize) > rva) return i;

		return INVALID_PE_VALUE;
	}

	unsigned long rva_to_offset(PIMAGE_NT_HEADERS headers, unsigned long rva, unsigned long size)
	{
		auto section_header{ IMAGE_FIRST_SECTION(headers) };
		const auto sections = headers->FileHeader.NumberOfSections;
		for (int i = 0; i < sections; i++)
		{
			if (section_header->VirtualAddress <= rva)
			{
				if ((section_header->VirtualAddress + section_header->Misc.VirtualSize) > rva)
				{
					rva -= section_header->VirtualAddress;
					rva += section_header->PointerToRawData;
					return rva < size ? rva : INVALID_PE_VALUE;
				}
			}
			section_header++;
		}

		return INVALID_PE_VALUE;
	}

	unsigned long get_export_offset(const unsigned char* file_data, unsigned long file_size, const char* export_name)
	{
		//Verify DOS Header
		auto dos_header{ reinterpret_cast<PIMAGE_DOS_HEADER>(const_cast<unsigned char*>(file_data)) };
		if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) return INVALID_PE_VALUE;

		//Verify PE Header
		auto nt_header{ reinterpret_cast<PIMAGE_NT_HEADERS>(const_cast<unsigned char*>(file_data + dos_header->e_lfanew)) };
		if (nt_header->Signature != IMAGE_NT_SIGNATURE) return INVALID_PE_VALUE;

		//Verify Export Directory
		auto header64{ nt_header->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC ? (reinterpret_cast<PIMAGE_NT_HEADERS64>(nt_header))->OptionalHeader.DataDirectory :
			(reinterpret_cast<PIMAGE_NT_HEADERS32>(nt_header))->OptionalHeader.DataDirectory };

		const auto export_directory_rva{ header64[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress };
		const auto export_directory_size{ header64[IMAGE_DIRECTORY_ENTRY_EXPORT].Size };
		auto export_directory_offset{ rva_to_offset(nt_header, export_directory_rva, file_size) };
		if (export_directory_offset == INVALID_PE_VALUE) return INVALID_PE_VALUE;

		//Read Export Directory
		auto export_directory{ reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(const_cast<unsigned char*>(file_data + export_directory_offset)) };
		const auto number_of_names{ export_directory->NumberOfNames };
		ULONG functions_offset = rva_to_offset(nt_header, export_directory->AddressOfFunctions, file_size);
		ULONG oridinals_offset = rva_to_offset(nt_header, export_directory->AddressOfNameOrdinals, file_size);
		ULONG names_offset = rva_to_offset(nt_header, export_directory->AddressOfNames, file_size);
		if (functions_offset == INVALID_PE_VALUE || oridinals_offset == INVALID_PE_VALUE || names_offset == INVALID_PE_VALUE) return INVALID_PE_VALUE;

		auto functions{ reinterpret_cast<unsigned long*>(const_cast<unsigned char*>(file_data + functions_offset)) };
		auto oridinals{ reinterpret_cast<unsigned short*>(const_cast<unsigned char*>(file_data + oridinals_offset)) };
		auto names{ reinterpret_cast<unsigned long*>(const_cast<unsigned char*>(file_data + names_offset)) };

		//Find Export
		auto export_offset{ INVALID_PE_VALUE };
		for (unsigned long i{}; i < number_of_names; i++)
		{
			const auto current_name_offset{ rva_to_offset(nt_header, names[i], file_size) };
			if (current_name_offset == INVALID_PE_VALUE) continue;

			const char* current_name = reinterpret_cast<const char*>(const_cast<unsigned char*>(file_data + current_name_offset));
			const auto current_function_rva{ functions[oridinals[i]] };

			//we ignore forwarded exports
			if (current_function_rva >= export_directory_rva && current_function_rva < export_directory_rva + export_directory_size) continue;

			if (std::char_traits<char>::compare(current_name, export_name, std::char_traits<char>::length(export_name)) == 0)  //compare the export name to the requested export
			{
				export_offset = rva_to_offset(nt_header, current_function_rva, file_size);
				break;
			}
		}

		return export_offset;
	}

	NTSTATUS initialize()
	{
		UNICODE_STRING file_name RTL_CONSTANT_STRING(L"\\SystemRoot\\system32\\ntdll.dll");
		OBJECT_ATTRIBUTES attributbes{};
		InitializeObjectAttributes(&attributbes, &file_name, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, nullptr, nullptr);

		if (KeGetCurrentIrql() != PASSIVE_LEVEL) return STATUS_UNSUCCESSFUL;

		HANDLE file_handle;
		IO_STATUS_BLOCK status_block;
		NTSTATUS status{ ZwCreateFile(&file_handle, GENERIC_READ, &attributbes, &status_block, nullptr, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ,
			FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, nullptr, 0) };
		if (NT_SUCCESS(status))
		{

			FILE_STANDARD_INFORMATION standard_information{};
			status = ZwQueryInformationFile(file_handle, &status_block, &standard_information, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);
			if (NT_SUCCESS(status))
			{
				static_file_size = standard_information.EndOfFile.LowPart;
				static_file_data = reinterpret_cast<unsigned char*>(memory::allocate(static_file_size, true));

				LARGE_INTEGER offset{};
				offset.LowPart = offset.HighPart = 0;
				status = ZwReadFile(file_handle, nullptr, nullptr, nullptr, &status_block, static_file_data, static_file_size, &offset, nullptr);

				if (!NT_SUCCESS(status)) memory::free(static_file_data);
			}

			ZwClose(file_handle);
		}

		return status;
	}

	int get_ssdt_index(const char* name)
	{
		if (static_file_data == nullptr) initialize();

		auto export_offset{ get_export_offset(static_file_data, static_file_size, name) };
		if (export_offset == INVALID_PE_VALUE) return -1;

		int ssdt_offset = -1;
		unsigned char* export_data = static_file_data + export_offset;
		for (int i = 0; i < 32 && export_offset + i < static_file_size; i++)
		{
			if (export_data[i] == 0xC2 || export_data[i] == 0xC3)  //RET
				break;

			if (export_data[i] == 0xB8)  //mov eax,X
			{
				ssdt_offset = *reinterpret_cast<int*>(export_data + i + 1);
				break;
			}
		}

		return ssdt_offset;
	}
}