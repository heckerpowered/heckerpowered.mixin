
PUBLIC vmx_launch
EXTERN vm_exit_handler:PROC

PUSHAQ MACRO
    push    rax
    push    rcx
    push    rdx
    push    rbx
    push    -1
    push    rbp
    push    rsi
    push    rdi
    push    r8
    push    r9
    push    r10
    push    r11
    push    r12
    push    r13
    push    r14
    push    r15
ENDM

POPAQ MACRO
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     r11
    pop     r10
    pop     r9
    pop     r8
    pop     rdi
    pop     rsi
    pop     rbp
    add     rsp, 8
    pop     rbx
    pop     rdx
    pop     rcx
    pop     rax
ENDM

.CONST 
VMX_OK EQU 0
VMX_ERROR_WITH_STATUS EQU 1
VMX_ERROR_WITHOUT_STATUS EQU 2

.CODE
;这个函数用于保存Guest环境后执行vmlaunch，再恢复Guest环境
;BOOLEAN AsmVmxLaunch(PVOID callBack,PVOID thisPoint);
vmx_launch PROC
	pushfq
	PUSHAQ
	
    mov rax,rcx;把InitVMCS函数指针放在rax
    mov rcx,rdx;在C++中调用成员函数要传入对象this指针,参数个数确定的时候，用rcx来传递,否则作为最后一个传
	mov rdx,rsp;传入InitVMCS的参数1 guestStack
	mov r8,VmLaunchToGuest;传入InitVMCS的参数2 guestResumeRip
	sub rsp,100h;提升栈顶，给一些局部变量分配足够的栈空间
	call rax;调用InitVMCS
	add rsp,100h
	
    ;若成功，不会执行到这里
	POPAQ
	popfq
	xor rax,rax
	ret

VmLaunchToGuest:

	POPAQ
	popfq
	xor rax,rax
	inc rax
	ret

vmx_launch ENDP

;拦截的VmExit事件触发的时候，从这里开始进入我们的处理函数VmexitHandler
vmm_entry_point PROC
	PUSHAQ			;当guest转入vmm时,通用寄存器并不会改变.而其它寄存器存放在vmcs guest域中,包括rflags

	mov rcx,rsp
	sub rsp,50h
	call vm_exit_handler;该函数执行有三种结果,一种是遇到非预期的vmexit直接断点.返回0继续运行,需要vmresume. 返回1退出vmx,回到guest
	add rsp,50h
	test rax,rax
	jz ExitVmx		;返回0则退出vmx

	POPAQ
	vmresume		;会根据vmcs的guest域进行恢复guest状态,只是通用寄存器需要手动恢复
	jmp ErrorHandler	;如果回Guest失败才会执行这里
ExitVmx:
	POPAQ
	vmxoff			;执行完后rax=rflags,rdx=原来的栈,rcx=导致vmexit的下一条指令地址
	jz ErrorHandler             ; if (ZF) jmp
    jc ErrorHandler             ; if (CF) jmp
    push rax
    popfq                  ; rflags <= GuestFlags
    mov rsp, rdx            ; rsp <= GuestRsp
    push rcx
    ret                     ; jmp AddressToReturn
ErrorHandler:
    int 3
vmm_entry_point ENDP



vmx_call PROC
    vmcall                  ; vmcall(hypercall_number, context)
    ret
vmx_call ENDP


_invd PROC
    invd
    ret
_invd ENDP

_invvpid PROC
    invvpid rcx, oword ptr [rdx]
    jz errorWithCode        ; if (ZF) jmp
    jc errorWithoutCode     ; if (CF) jmp
    xor rax, rax            ; return VMX_OK
    ret

errorWithoutCode:
    mov rax, VMX_ERROR_WITHOUT_STATUS
    ret

errorWithCode:
    mov rax, VMX_ERROR_WITH_STATUS
    ret
_invvpid ENDP


; void AsmWriteGDT(_In_ const GDTR *gdtr);
write_gdt PROC
    lgdt fword ptr [rcx]
    ret
write_gdt ENDP

; void AsmWriteLDTR(_In_ USHORT local_segmeng_selector);
write_ldtr PROC
    lldt cx
    ret
write_ldtr ENDP

; USHORT AsmReadLDTR();
read_ldtr PROC
    sldt ax
    ret
read_ldtr ENDP

; void AsmWriteTR(_In_ USHORT task_register);
write_tr PROC
    ltr cx
    ret
write_tr ENDP

; USHORT AsmReadTR();
read_tr PROC
    str ax
    ret
read_tr ENDP

; void AsmWriteES(_In_ USHORT segment_selector);
write_es PROC
    mov es, cx
    ret
write_es ENDP

; USHORT AsmReadES();
read_es PROC
    mov ax, es
    ret
read_es ENDP

; void AsmWriteCS(_In_ USHORT segment_selector);
write_cs PROC
    mov cs, cx
    ret
write_cs ENDP

; USHORT AsmReadCS();
read_cs PROC
    mov ax, cs
    ret
read_cs ENDP

; void AsmWriteSS(_In_ USHORT segment_selector);
write_ss PROC
    mov ss, cx
    ret
write_ss ENDP

; USHORT AsmReadSS();
read_ss PROC
    mov ax, ss
    ret
read_ss ENDP

; void AsmWriteDS(_In_ USHORT segment_selector);
write_ds PROC
    mov ds, cx
    ret
write_ds ENDP

; USHORT AsmReadDS();
read_ds PROC
    mov ax, ds
    ret
read_ds ENDP

; void AsmWriteFS(_In_ USHORT segment_selector);
write_fs PROC
    mov fs, cx
    ret
write_fs ENDP

; USHORT AsmReadFS();
read_fs PROC
    mov ax, fs
    ret
read_fs ENDP

; void AsmWriteGS(_In_ USHORT segment_selector);
write_gs PROC
    mov gs, cx
    ret
write_gs ENDP

; USHORT AsmReadGS();
read_gs PROC
    mov ax, gs
    ret
read_gs ENDP

; ULONG_PTR AsmLoadAccessRightsByte(_In_ ULONG_PTR segment_selector);
load_access_rights_byte PROC
    lar rax, rcx
    ret
load_access_rights_byte ENDP

END