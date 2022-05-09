#include "virtual_hook.hpp"
#ifdef ENABLE_VIRTUALIZATION
namespace hook::virtual_hook
{
	std::unordered_multimap<unsigned __int64, virtual_hook>* hooked_functions;

	std::size_t get_patch_size(void* function) noexcept
	{
		const auto buffer{ reinterpret_cast<char*>(function) };
		const auto end{ buffer + 45 };
		nmd_x86_instruction instruction{};
		char formatted_instruction[128]{};

		for (std::size_t i{}; i < 45; i += instruction.length)
		{
			if (!nmd_decode_x86(buffer + i, end - (buffer + i), &instruction, NMD_X86_MODE::NMD_X86_MODE_64,
				NMD_X86_DECODER_FLAGS::NMD_X86_DECODER_FLAGS_MINIMAL)) { break; }

			#pragma warning(push)
			#pragma warning(disable:4245)
			nmd_format_x86(&instruction, formatted_instruction, NMD_X86_INVALID_RUNTIME_ADDRESS,
				NMD_X86_FORMATTER_FLAGS::NMD_X86_FORMAT_FLAGS_DEFAULT);
			#pragma warning(pop)

			if (i >= 12) { return i; }
		}

		return 0;
	}

	void initialize() noexcept
	{
		hooked_functions = new std::unordered_multimap<unsigned __int64, virtual_hook>();
	}

	std::optional<virtual_hook> get_hook(unsigned __int64 address) noexcept
	{
		if ((address &= 0xFFFFFFFFFFFFF000) == 0) { return {}; }
		const auto hook{ hooked_functions->find(address) };

		if (hook == hooked_functions->end()) { return {}; }
		if (hook->second.free) { return {}; }
		return std::make_optional<virtual_hook>(hook->second);
	}

	void* hook(unsigned __int64 address, void* proxy) noexcept
	{
		if (hooked_functions->contains(address)) { return nullptr; }

		unsigned char jmp_proxy[] = "\x48\xB8\x00\x00\x00\x00\x00\x00\x00\x00\x50\xC3";
		unsigned char jmp_origin[] = "\xFF\x25\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF";

		*reinterpret_cast<void**>(jmp_proxy + 2) = &proxy;
		const auto patch_size{ get_patch_size(reinterpret_cast<void*>(address)) };
		unsigned __int64 jmp_original_address{ address + patch_size };
		*reinterpret_cast<void**>(jmp_origin + 6) = &jmp_original_address;

		auto fake_page{ reinterpret_cast<char*>(memory::allocate_contiguous(patch_size + 14)) };
		memcpy(fake_page, reinterpret_cast<const void*>(address & 0xFFFFFFFFFFFFF000), PAGE_SIZE);

		void* original_function_code = memory::allocate_contiguous(patch_size + 14);
		memset(original_function_code, 0x90, patch_size + 14);
		memcpy(original_function_code, reinterpret_cast<const void*>(address), patch_size);
		memcpy(reinterpret_cast<char*>(original_function_code) + patch_size, jmp_origin, 14);

		const auto offset{ address - (address & 0xFFFFFFFFFFFFF000) };
		memset(fake_page + offset, 0x90, patch_size);
		memcpy(fake_page + offset, &jmp_origin, 12);
		virtual_hook info{
			unsigned __int64(MmGetPhysicalAddress(reinterpret_cast<void*>(address & 0xFFFFFFFFFFFFF000)).QuadPart),
			MmGetPhysicalAddress(fake_page).QuadPart & 0xFFFFFFFFFFFFF000,
			unsigned __int64(fake_page),
			address,
			unsigned __int64(original_function_code)
		};

		hooked_functions->emplace(info.fake_page, info);
		hooked_functions->emplace(info.real_page, info);
		hooked_functions->emplace(info.original_function, info);

		virtualization::assembly::vmx_call(unsigned __int64(virtualization::assembly::vm_call::call_ept_hook),
			unsigned __int64(&info));
		return original_function_code;
	}

	void unhook(unsigned __int64 address) noexcept
	{
		auto info{ get_hook(address) };
		if (!info.has_value()) { return; }

		auto& value{ info.value() };
		value.free = true;

		virtualization::assembly::vmx_call(unsigned __int64(virtualization::assembly::vm_call::call_ept_unhook), unsigned __int64(&value));
		memory::free(reinterpret_cast<void*>(value.original_function_code));
		memory::free(reinterpret_cast<void*>(value.fake_page));
	}

	void unhook() noexcept
	{
		if (hooked_functions == nullptr) { return; }
		for (auto&& hook : *hooked_functions)
		{
			if (hook.second.free) { continue; }
			unhook(hook.second.original_function);
		}
	}
}
#endif