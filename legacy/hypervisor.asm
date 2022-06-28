extern virtualize_current_system : proc
extern vmx_vmexit_handler : proc
extern vmx_return_stack_pointer_for_vmxoff : proc
extern vmx_return_instruction_pointer_for_vmxoff : proc
extern vmx_vmresume : proc

.code

VMX_ERROR_CODE_SUCCESS              = 0
VMX_ERROR_CODE_FAILED_WITH_STATUS   = 1
VMX_ERROR_CODE_FAILED               = 2

enable_vmx_operation proc public

	xor rax, rax ; Clear the rax
	mov rax, cr4
	or rax, 02000h ; Set the 14th bit
	mov cr4, rax
	ret

enable_vmx_operation endp

save_hypervisor_state proc
	
	;
	; add it because the alignment of the RSP when calling the target function
	; should be aligned to 16 (otherwise cause performance issues)
	;
	push 0

	pushfq ; save r/eflag

	push rax
	push rcx
	push rdx
	push rbx
    push rbp
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15

	;
	; It a x64 FastCall function so the first parameter should go to rcx
	;
	sub rsp, 0100h

	mov rcx, rsp
    call virtualize_current_system

	;
	; we should never reach here as we execute vmlaunch in the above function.
	; if rax is FALSE then it's an indication of error
	;

	int 3	
    jmp restore_hypervisor_state

save_hypervisor_state endp

restore_hypervisor_state PROC
    
    add rsp, 0100h
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    pop rdx
    pop rcx
    pop rax
    
    popfq	; restore r/eflags
    add rsp, 08h ; because we pushed an etra qword to make it aligned
    ret
    
restore_hypervisor_state ENDP

vm_exit_handler proc

	    
    push 0  ; we might be in an unaligned stack state, so the memory before stack might cause 
            ; irql less or equal as it doesn't exist, so we just put some extra space avoid
            ; these kind of erros

    pushfq

    ; ------------ Save XMM Registers ------------
    ;
    ;   ;;;;;;;;;;;; 16 Byte * 16 Byte = 256 + 4  = 260 (0x106 == 0x110 but let's align it to have better performance) ;;;;;;;;;;;;
    ;   sub     rsp, 0110h
    ;
    ;   movaps  xmmword ptr [rsp+000h], xmm0    ; each xmm register 128 bit (16 Byte)
    ;   movaps  xmmword ptr [rsp+010h], xmm1
    ;   movaps  xmmword ptr [rsp+020h], xmm2
    ;   movaps  xmmword ptr [rsp+030h], xmm3
    ;   movaps  xmmword ptr [rsp+040h], xmm4
    ;   movaps  xmmword ptr [rsp+050h], xmm5
    ;   movaps  xmmword ptr [rsp+060h], xmm6 
    ;   movaps  xmmword ptr [rsp+070h], xmm7
    ;   movaps  xmmword ptr [rsp+080h], xmm8
    ;   movaps  xmmword ptr [rsp+090h], xmm9
    ;   movaps  xmmword ptr [rsp+0a0h], xmm10
    ;   movaps  xmmword ptr [rsp+0b0h], xmm11
    ;   movaps  xmmword ptr [rsp+0c0h], xmm12
    ;   movaps  xmmword ptr [rsp+0d0h], xmm13
    ;   movaps  xmmword ptr [rsp+0e0h], xmm14
    ;   movaps  xmmword ptr [rsp+0f0h], xmm15 
    ;   stmxcsr dword ptr [rsp+0100h]           ; MxCsr is 4 Byte
    ;
    ;---------------------------------------------

    push r15
    push r14
    push r13
    push r12
    push r11
    push r10
    push r9
    push r8        
    push rdi
    push rsi
    push rbp
    push rbp	; rsp
    push rbx
    push rdx
    push rcx
    push rax	
    
    mov rcx, rsp		; Fast call argument to PGUEST_REGS
    sub	rsp, 020h		; Free some space for Shadow Section
    call vmx_vmexit_handler
    add	rsp, 020h		; Restore the state
    
    cmp	al, 1	; Check whether we have to turn off VMX or Not (the result is in RAX)
    je vmx_off_handler
    
restore_state:
    pop rax
    pop rcx
    pop rdx
    pop rbx
    pop rbp		; rsp
    pop rbp
    pop rsi
    pop rdi 
    pop r8
    pop r9
    pop r10
    pop r11
    pop r12
    pop r13
    pop r14
    pop r15

    ; ------------ Restore XMM Registers ------------
    ;
    ;   movaps xmm0, xmmword ptr [rsp+000h]
    ;   movaps xmm1, xmmword ptr [rsp+010h]
    ;   movaps xmm2, xmmword ptr [rsp+020h]
    ;   movaps xmm3, xmmword ptr [rsp+030h]
    ;   movaps xmm4, xmmword ptr [rsp+040h]
    ;   movaps xmm5, xmmword ptr [rsp+050h]
    ;   movaps xmm6, xmmword ptr [rsp+060h]
    ;   movaps xmm7, xmmword ptr [rsp+070h]
    ;   movaps xmm8, xmmword ptr [rsp+080h]
    ;   movaps xmm9, xmmword ptr [rsp+090h]
    ;   movaps xmm10, xmmword ptr [rsp+0a0h]
    ;   movaps xmm11, xmmword ptr [rsp+0b0h]
    ;   movaps xmm12, xmmword ptr [rsp+0c0h]
    ;   movaps xmm13, xmmword ptr [rsp+0d0h]
    ;   movaps xmm14, xmmword ptr [rsp+0e0h]
    ;   movaps xmm15, xmmword ptr [rsp+0f0h]
    ;
    ;   ldmxcsr dword ptr [rsp+0100h]          
    ;   
    ;   add     rsp, 0110h
    ; ----------------------------------------------

    popfq

    sub rsp, 0100h      ; to avoid error in future functions
    jmp vmx_vmresume
    

vm_exit_handler endp

vmx_off_handler PROC
    
    sub rsp, 020h ; shadow space
    call vmx_return_stack_pointer_for_vmxoff
    add rsp, 020h ; remove for shadow space
    
    mov [rsp+88h], rax  ; now, rax contains rsp
    
    sub rsp, 020h      ; shadow space
    call vmx_return_instruction_pointer_for_vmxoff
    add rsp, 020h      ; remove for shadow space
    
    mov rdx, rsp       ; save current rsp
    
    mov rbx, [rsp+88h] ; read rsp again
    
    mov rsp, rbx
    
    push rax            ; push the return address as we changed the stack, we push
                  		; it to the new stack
    
    mov rsp, rdx        ; restore previous rsp
                    
    sub rbx,08h         ; we push sth, so we have to add (sub) +8 from previous stack
                   		; also rbx already contains the rsp
    mov [rsp+88h], rbx  ; move the new pointer to the current stack
    
restore_state:
    pop rax
    pop rcx
    pop rdx
    pop rbx
    pop rbp		         ; rsp
    pop rbp
    pop rsi
    pop rdi 
    pop r8
    pop r9
    pop r10
    pop r11
    pop r12
    pop r13
    pop r14
    pop r15

    ; ------------ Restore XMM Registers ------------
    ;
    ;    movaps xmm0, xmmword ptr [rsp+000h]
    ;    movaps xmm1, xmmword ptr [rsp+010h]
    ;    movaps xmm2, xmmword ptr [rsp+020h]
    ;    movaps xmm3, xmmword ptr [rsp+030h]
    ;    movaps xmm4, xmmword ptr [rsp+040h]
    ;    movaps xmm5, xmmword ptr [rsp+050h]
    ;    movaps xmm6, xmmword ptr [rsp+060h]
    ;    movaps xmm7, xmmword ptr [rsp+070h]
    ;    movaps xmm8, xmmword ptr [rsp+080h]
    ;    movaps xmm9, xmmword ptr [rsp+090h]
    ;    movaps xmm10, xmmword ptr [rsp+0a0h]
    ;    movaps xmm11, xmmword ptr [rsp+0b0h]
    ;    movaps xmm12, xmmword ptr [rsp+0c0h]
    ;    movaps xmm13, xmmword ptr [rsp+0d0h]
    ;    movaps xmm14, xmmword ptr [rsp+0e0h]
    ;    movaps xmm15, xmmword ptr [rsp+0f0h]
    ;
    ;    ldmxcsr dword ptr [rsp+0100h]          
    ;    
    ;    add     rsp, 0110h
    ; ----------------------------------------------

    popfq
    pop		rsp     ; restore rsp

    ret             ; jump back to where we called Vmcall

vmx_off_handler ENDP

get_access_right proc

	lar rax, rcx
	jz no_error
	xor rax, rax
no_error:
	ret
get_access_right endp

get_cs proc

	mov rax, cs
	ret

get_cs endp

get_ds proc

	mov rax, ds
	ret

get_ds endp

get_es proc

	mov rax, es
	ret

get_es endp

get_ss proc

	mov rax, ss
	ret

get_ss endp

get_fs proc

    mov rax, fs
    ret

get_fs endp

get_gs proc

	mov rax, gs
	ret

get_gs endp

get_ldtr proc

	sldt rax
	ret

get_ldtr endp

get_tr proc

	str rax
	ret

get_tr endp

get_gdt_base proc
	
	local gdtr[10] : byte
	sgdt gdtr
	mov rax, qword ptr gdtr[2]
	ret

get_gdt_base endp

get_gdt_limit proc

	local gdtr[10] : byte

	sgdt gdtr
	mov ax, word ptr gdtr[10]
	ret

get_gdt_limit endp

get_idt_base proc

	local idtr[10] : byte

	sidt idtr
	mov rax, qword ptr idtr[2]
	ret

get_idt_base endp

get_idt_limit proc

	local idtr[10] : byte

	sidt idtr
	mov ax, word ptr idtr[0]
	ret

get_idt_limit endp


_invept proc

    invvpid rcx, oword ptr [rdx]
    jz      ErrorWithStatus
    jc      ErrorCodeFailed
    xor     rax, rax
    ret
    ;
ErrorWithStatus:
    mov     rax, VMX_ERROR_CODE_FAILED_WITH_STATUS
    ret

ErrorCodeFailed:
    mov     rax, VMX_ERROR_CODE_FAILED
    ret
    ;
_invept endp

get_rflags proc

	pushfq
	pop rax
	ret

get_rflags endp

end