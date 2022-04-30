#include "native.hpp"

namespace native
{
	unsigned long prologue32(unsigned char* buffer) noexcept
	{
		*buffer = 0x55;
		*reinterpret_cast<unsigned short*>(buffer + 1) = 0xE589;
		return 3;
	}

	unsigned long epilogue32(unsigned char* buffer, int ret_size) noexcept
	{
		*reinterpret_cast<unsigned short*>(buffer) = 0xEC89;
		*(buffer + 2) = 0x5D;
		*(buffer + 3) = 0xC2;
		*reinterpret_cast<unsigned short*>(buffer + 4) = static_cast<unsigned short>(ret_size);

		return 6;
	}

	unsigned long call32(unsigned char* buffer, void* function, const std::vector<unsigned long>& args) noexcept
	{
		unsigned long offset{};

		for (auto i = args.rbegin(); i != args.rend(); i++)
		{
			*reinterpret_cast<unsigned short*>(buffer + offset) = 0x68;                 // push arg
			*reinterpret_cast<unsigned long*>(buffer + offset + 1) = *i;        //
			offset += 5;
		}

		*reinterpret_cast<unsigned char*>(buffer + offset) = 0xB8;                      // mov eax, pFn
		*reinterpret_cast<unsigned long*>(buffer + offset + 1) = static_cast<unsigned long>(reinterpret_cast<unsigned __int64>(function)); //
		offset += 5;

		*reinterpret_cast<unsigned short*>(buffer + offset) = 0xD0FF;                   // call eax
		offset += 2;
		return offset;
	}

	unsigned long sync32(unsigned char* buffer, NTSTATUS& status, void* set_event, HANDLE event) noexcept
	{
		unsigned long offset{};

		*reinterpret_cast<unsigned char*>(buffer + offset) = 0xA3;                  // mov [status], eax
		*reinterpret_cast<void**>(buffer + offset + 1) = &status;           //
		offset += 5;

		*reinterpret_cast<unsigned short*>(buffer + offset) = 0x006A;               // push FALSE
		offset += 2;

		*reinterpret_cast<unsigned char*>(buffer + offset) = 0x68;                  // push event
		*reinterpret_cast<unsigned long*>(buffer + offset + 1) = static_cast<unsigned long>(reinterpret_cast<unsigned __int64>(event));  //
		offset += 5;

		*reinterpret_cast<unsigned char*>(buffer + offset) = 0xB8;                  // mov eax, set_event
		*reinterpret_cast<unsigned long*>(buffer + offset + 1) = static_cast<unsigned long>(reinterpret_cast<unsigned __int64>(set_event));//
		offset += 5;

		*reinterpret_cast<unsigned short*>(buffer + offset) = 0xD0FF;               // call eax
		offset += 2;

		return offset;
	}

	unsigned long prologue64(unsigned char* buffer) noexcept
	{
		*reinterpret_cast<unsigned long*>(buffer + 0) = 0x244C8948;       // mov [rsp + 0x08], rcx
		*reinterpret_cast<unsigned char*>(buffer + 4) = 0x8;              // 
		*reinterpret_cast<unsigned long*>(buffer + 5) = 0x24548948;       // mov [rsp + 0x10], rdx
		*reinterpret_cast<unsigned char*>(buffer + 9) = 0x10;             // 
		*reinterpret_cast<unsigned long*>(buffer + 10) = 0x2444894C;      // mov [rsp + 0x18], r8
		*reinterpret_cast<unsigned char*>(buffer + 14) = 0x18;            // 
		*reinterpret_cast<unsigned long*>(buffer + 15) = 0x244C894C;      // mov [rsp + 0x20], r9
		*reinterpret_cast<unsigned char*>(buffer + 19) = 0x20;            // 
		return 20;
	}

	unsigned long epilogue64(unsigned char* buffer, int ret_size [[maybe_unused]] ) noexcept
	{
		*reinterpret_cast<unsigned long*>(buffer + 0) = 0x244C8B48;       // mov rcx, [rsp + 0x08]
		*reinterpret_cast<unsigned char*>(buffer + 4) = 0x8;              // 
		*reinterpret_cast<unsigned long*>(buffer + 5) = 0x24548B48;       // mov rdx, [rsp + 0x10]
		*reinterpret_cast<unsigned char*>(buffer + 9) = 0x10;             // 
		*reinterpret_cast<unsigned long*>(buffer + 10) = 0x24448B4C;      // mov r8, [rsp + 0x18]
		*reinterpret_cast<unsigned char*>(buffer + 14) = 0x18;            // 
		*reinterpret_cast<unsigned long*>(buffer + 15) = 0x244C8B4C;      // mov r9, [rsp + 0x20]
		*reinterpret_cast<unsigned char*>(buffer + 19) = 0x20;            // 
		*reinterpret_cast<unsigned char*>(buffer + 20) = 0xC3;            // ret
		return 21;
	}

	unsigned long call64(unsigned char* buffer, void* function, const std::vector<unsigned __int64>& args) noexcept
	{
		unsigned short rsp_diff{ 0x28 };
		unsigned long offset{};
		const auto argc{ args.size() };
		if (argc > 4)
		{
			rsp_diff = static_cast<unsigned short>(argc * sizeof(unsigned __int64));
			if (rsp_diff % 0x10) rsp_diff = ((rsp_diff / 0x10) + 1) * 0x10;
			rsp_diff += 8;
		}

		// sub rsp, rsp_diff
		*reinterpret_cast<unsigned long*>(buffer + offset) = (0x00EC8348 | rsp_diff << 24);
		offset += 4;

		int index{};
		if (argc > 0)
		{
			*reinterpret_cast<unsigned short*>(buffer + offset) = 0xB948;           // mov rcx, arg
			*reinterpret_cast<void**>(buffer + offset + 2) = reinterpret_cast<void*>(args[index++]);           //
			offset += 10;
		}

		if (argc > 1)
		{
			*reinterpret_cast<unsigned short*>(buffer + offset) = 0xBA48;           // mov rdx, arg
			*reinterpret_cast<void**>(buffer + offset + 2) = reinterpret_cast<void*>(args[index++]);           //
			offset += 10;
		}

		if (argc > 2)
		{
			*reinterpret_cast<unsigned short*>(buffer + offset) = 0xB849;           // mov r8, arg
			*reinterpret_cast<void**>(buffer + offset + 2) = reinterpret_cast<void*>(args[index++]);           //
			offset += 10;
		}

		if (argc > 3)
		{
			*reinterpret_cast<unsigned short*>(buffer + offset) = 0xB949;           // mov r9, arg
			*reinterpret_cast<void**>(buffer + offset + 2) = reinterpret_cast<void*>(args[index++]);           //
			offset += 10;
		}

		for (unsigned __int64 i{ 4 }; i < argc; i++)
		{
			auto arg{ reinterpret_cast<void*>(args[index++]) };

			*reinterpret_cast<unsigned short*>(buffer + offset) = 0xB848;           // mov rcx, arg
			*reinterpret_cast<void**>(buffer + offset + 2) = arg;           //
			offset += 10;

			// mov [rsp + i*8], rax
			*reinterpret_cast<unsigned long*>(buffer + offset) = 0x24448948;
			*reinterpret_cast<unsigned char*>(buffer + offset + 4) = static_cast<unsigned char>(0x20 + (static_cast<unsigned __int64>(i) - 4) * sizeof(void*));
			offset += 5;
		}


		*reinterpret_cast<unsigned short*>(buffer + offset) = 0xB848;               // mov rax, pFn
		*reinterpret_cast<void**>(buffer + offset + 2) = function;               //
		offset += 10;

		*reinterpret_cast<unsigned short*>(buffer + offset) = 0xD0FF;               // call rax
		offset += 2;

		// add rsp, rsp_diff
		*reinterpret_cast<unsigned long*>(buffer + offset) = (0x00C48348 | rsp_diff << 24);
		offset += 4;

		return offset;
	}

	unsigned long sync64(unsigned char* buffer, NTSTATUS& status, void* set_event, HANDLE event) noexcept
	{
		unsigned long offset{};

		*reinterpret_cast<unsigned short*>(buffer + offset) = 0xA348;           // mov [pStatus], rax
		*reinterpret_cast<void**>(buffer + offset + 2) = &status;       //
		offset += 10;

		*reinterpret_cast<unsigned short*>(buffer + offset) = 0xB948;           // mov rcx, event
		*reinterpret_cast<PHANDLE>(buffer + offset + 2) = event;       //
		offset += 10;

		*(buffer + offset) = 0x48;                      // xor rdx, rdx
		*reinterpret_cast<unsigned short*>(buffer + offset + 1) = 0xD231;       //
		offset += 3;

		*reinterpret_cast<unsigned short*>(buffer + offset) = 0xB848;           // mov rax, set_event
		*reinterpret_cast<void**>(buffer + offset + 2) = set_event;     //
		offset += 10;

		*reinterpret_cast<unsigned short*>(buffer + offset) = 0xD0FF;           // call rax
		offset += 2;

		return offset;
	}

	unsigned long prologue(bool wow64, unsigned char* buffer) noexcept
	{
		return wow64 ? prologue64(buffer) : prologue32(buffer);
	}

	unsigned long epilogue(bool wow64, unsigned char* buffer, int ret_size) noexcept
	{
		return wow64 ? epilogue64(buffer, ret_size) : epilogue32(buffer, ret_size);
	}

	unsigned long call(bool wow64, unsigned char* buffer, void* function, const std::vector<unsigned __int64>& args) noexcept
	{
		if (wow64) return call64(buffer, function, args);

		std::vector<unsigned long> copy;
		for (auto&& value : args) copy.push_back(static_cast<unsigned long>(value));

		return call32(buffer, function, copy);
	}

	unsigned long sync(bool wow64, unsigned char* buffer, NTSTATUS& status, void* set_event, HANDLE event) noexcept
	{
		return wow64 ? sync64(buffer, status, set_event, event) : sync32(buffer, status, set_event, event);
	}
}