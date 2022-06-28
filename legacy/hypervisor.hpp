#pragma once

extern "C" inline void enable_vmx_operation();
extern "C" inline void save_hypervisor_state();
extern "C" inline void restore_hypervisor_state();
extern "C" inline void vm_exit_handler();
extern "C" inline std::uint32_t get_access_right(std::uint16_t selector);
extern "C" inline std::uint16_t get_cs();
extern "C" inline std::uint16_t get_ds();
extern "C" inline std::uint16_t get_es();
extern "C" inline std::uint16_t get_ss();
extern "C" inline std::uint16_t get_fs();
extern "C" inline std::uint16_t get_gs();
extern "C" inline std::uint16_t get_ldtr();
extern "C" inline std::uint16_t get_tr();
extern "C" inline std::uint64_t get_gdt_base();
extern "C" inline std::uint16_t get_gdt_limit();
extern "C" inline std::uint64_t get_idt_base();
extern "C" inline std::uint16_t get_idt_limit();
extern "C" inline std::uint16_t get_rflags();
extern "C" inline std::uint8_t _invept(unsigned long type, void* descriptors);