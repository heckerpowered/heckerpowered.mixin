
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
;����������ڱ���Guest������ִ��vmlaunch���ٻָ�Guest����
;BOOLEAN AsmVmxLaunch(PVOID callBack,PVOID thisPoint);
vmx_launch PROC
	pushfq
	PUSHAQ
	
    mov rax,rcx;��InitVMCS����ָ�����rax
    mov rcx,rdx;��C++�е��ó�Ա����Ҫ�������thisָ��,��������ȷ����ʱ����rcx������,������Ϊ���һ����
	mov rdx,rsp;����InitVMCS�Ĳ���1 guestStack
	mov r8,VmLaunchToGuest;����InitVMCS�Ĳ���2 guestResumeRip
	sub rsp,100h;����ջ������һЩ�ֲ����������㹻��ջ�ռ�
	call rax;����InitVMCS
	add rsp,100h
	
    ;���ɹ�������ִ�е�����
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

;���ص�VmExit�¼�������ʱ�򣬴����￪ʼ�������ǵĴ�����VmexitHandler
vmm_entry_point PROC
	PUSHAQ			;��guestת��vmmʱ,ͨ�üĴ���������ı�.�������Ĵ��������vmcs guest����,����rflags

	mov rcx,rsp
	sub rsp,50h
	call vm_exit_handler;�ú���ִ�������ֽ��,һ����������Ԥ�ڵ�vmexitֱ�Ӷϵ�.����0��������,��Ҫvmresume. ����1�˳�vmx,�ص�guest
	add rsp,50h
	test rax,rax
	jz ExitVmx		;����0���˳�vmx

	POPAQ
	vmresume		;�����vmcs��guest����лָ�guest״̬,ֻ��ͨ�üĴ�����Ҫ�ֶ��ָ�
	jmp ErrorHandler	;�����Guestʧ�ܲŻ�ִ������
ExitVmx:
	POPAQ
	vmxoff			;ִ�����rax=rflags,rdx=ԭ����ջ,rcx=����vmexit����һ��ָ���ַ
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