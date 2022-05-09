#include "infinity_hook.hpp"

namespace hook::infinity_hook {
	std::unordered_map<void*, void*>* hooked_functions;

	void __fastcall callback(unsigned long ssdt_index [[maybe_unused]], void** ssdt_address) {
		const auto result = hooked_functions->find(*ssdt_address);
		if (result != hooked_functions->end()) *ssdt_address = result->second;
	}

	NTSTATUS initialize() {
		hooked_functions = new std::unordered_map<void*, void*>();
		return k_hook::initialize(callback) && k_hook::start() ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
	}

	void hook_export(const wchar_t* function_name, void* address) noexcept {
		auto function = proc::get_kernel_procedure(function_name);
		if (function == nullptr) {
			println("[WARNING] Unable to find function \"%ls\"", function_name);
			return;
		}

		hooked_functions->emplace(function, address);
	}

	void hook_ssdt(const char* ssdt_name, void* address) noexcept {
		const int ssdt_index{ ssdt::get_ssdt_index(ssdt_name) };
		if (ssdt_index == -1) {
			println("[WARNING] Unable to find ssdt function \"%s\"", ssdt_name);
			return;
		}

		hooked_functions->emplace(ext::get_ssdt_entry(ssdt_index), address);
	}

	inline void hook_function(void* function, void* address) noexcept {
		hooked_functions->emplace(function, address);
	}
}