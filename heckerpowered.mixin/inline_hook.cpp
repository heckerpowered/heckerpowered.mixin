#include "pch.hpp"

namespace hook::inline_hook
{
	std::unordered_map<void*, std::tuple<void*, unsigned char*, std::size_t>>* hooked_functions;

	void initialize() noexcept
	{
		hooked_functions = new std::unordered_map<void*, std::tuple<void*, unsigned char*, std::size_t>>();
		lde::initialize();
	}

	std::size_t get_patch_size(unsigned char* address) noexcept
	{
		size_t length_count{}, length{};
		while (length_count < 14)
		{
			length = lde::lde(address, 64);
			address += length;
			length_count += length;
		}

		return length_count;
	}

	void* hook_internal(void* victim, void* target, void*& original, std::size_t& patch_size)
	{
		patch_size = get_patch_size(reinterpret_cast<unsigned char*>(victim));
		auto original_header{ memory::allocate(patch_size) };
		auto irql{ memory::disable_interrupt() };
		memcpy(original_header, victim, patch_size);
		memory::enable_interrupt(irql);

		auto original_function{ memory::allocate(patch_size + 14) };
		memset(original_function, 0x90, patch_size + 14);

		unsigned char jmp_code[]{ "\xFF\x25\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF" };
		unsigned char jmp_code_function[]{ "\xFF\x25\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF" };

		auto begin{ reinterpret_cast<unsigned __int64>(victim) + patch_size };
		memcpy(jmp_code_function + 6, &begin, sizeof(begin));
		memcpy(original_function, original_header, patch_size);
		memcpy(reinterpret_cast<unsigned char*>(original_function) + patch_size, jmp_code_function, 14);
		original = original_function;

		begin = reinterpret_cast<unsigned __int64>(target);
		memcpy(jmp_code + 6, &begin, sizeof(begin));

		irql = memory::disable_interrupt();
		memset(victim, 0x90, patch_size);
		memcpy(victim, jmp_code, 14);
		memory::enable_interrupt(irql);
		return original_header;
	}

	void unhook_internal(void* victim, void* original, std::size_t patch_size)
	{
		auto irql{ memory::disable_interrupt() };
		memcpy(victim, original, patch_size);
		memory::enable_interrupt(irql);
	}

	void uninstall_hooks() noexcept
	{
		for (auto&& function : *hooked_functions) { unhook_internal(function.first, std::get<1>(function.second), std::get<2>(function.second)); }
	}

	void* get_unhooked(void* victim) noexcept
	{
		const auto result{ hooked_functions->find(victim) };
		if (result == hooked_functions->end()) { return nullptr; }
		return std::get<0>(result->second);
	}

	void hook(void* victim, void* target) noexcept
	{
		if (hooked_functions == nullptr) return;

		void* original{};
		std::size_t patch_size{};
		auto header{ hook_internal(victim, target, original, patch_size) };
		hooked_functions->emplace(victim, std::make_tuple(original, reinterpret_cast<unsigned char*>(header), patch_size));
	}
}