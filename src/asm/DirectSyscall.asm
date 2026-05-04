; IronLock x64 Assembly stubs
.code

; NTSTATUS DirectSyscall(uint32_t num, PVOID a1, PVOID a2, PVOID a3, PVOID a4, PVOID a5, PVOID a6)
; RCX = num, RDX = a1, R8 = a2, R9 = a3, [RSP+40] = a4, [RSP+48] = a5, [RSP+56] = a6

DirectSyscall PROC
    mov eax, ecx        ; Syscall number to EAX
    mov r10, rdx        ; 1st arg to R10
    mov rdx, r8         ; 2nd arg to RDX
    mov r8, r9          ; 3rd arg to R8
    mov r9, [rsp + 40]  ; 4th arg to R9

    ; The kernel expects arguments 5 and 6 on the stack at [RSP + 40] and [RSP + 48]
    ; However, we must account for the return address and the shadow space.
    ; We need to preserve the stack state.

    ; To pass 5th and 6th args correctly, we need to ensure they are in the
    ; correct position for the 'syscall' instruction.
    ; On Windows x64, the 'syscall' instruction doesn't use the stack,
    ; it's the kernel handler that reads the stack from the user mode RSP.

    ; We need to move [rsp+48] to [rsp+40] and [rsp+56] to [rsp+48]
    ; but we can't overwrite the shadow space we might need.
    ; Actually, for syscall, we just need the registers r10, rdx, r8, r9
    ; and the rest on the stack.

    sub rsp, 28h        ; Allocate shadow space for the syscall if the kernel expects it

    mov rax, [rsp + 48 + 28h] ; Adjust for the sub rsp
    mov [rsp + 20h], rax      ; 5th arg
    mov rax, [rsp + 56 + 28h]
    mov [rsp + 28h], rax      ; 6th arg

    mov eax, ecx
    syscall

    add rsp, 28h
    ret
DirectSyscall ENDP

; bool CheckVMwareBackdoorInternal()
CheckVMwareBackdoorInternal PROC
    push rbx
    mov eax, 56584D48h ; 'VMXh'
    mov ebx, 0
    mov ecx, 10        ; Get version
    mov edx, 5658h     ; port
    in eax, dx
    cmp ebx, 56584D48h
    setz al
    pop rbx
    ret
CheckVMwareBackdoorInternal ENDP

IL_OpaquePredicate PROC
    xor rax, rax
    jz label1
    db 0EAh, 012h, 034h, 056h, 078h
label1:
    ret
IL_OpaquePredicate ENDP

IL_JunkCode PROC
    push rax
    xor rax, rax
    test rax, rax
    jnz label_junk
    pop rax
    ret
label_junk:
    db 0FFh, 012h, 034h, 056h
    pop rax
    ret
IL_JunkCode ENDP

END
