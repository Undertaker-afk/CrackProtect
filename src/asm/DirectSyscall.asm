; IronLock Final x64 Assembly stubs
.code

; NTSTATUS DirectSyscall(uint32_t num, PVOID a1, PVOID a2, PVOID a3, PVOID a4, PVOID a5, PVOID a6)
DirectSyscall PROC
    mov eax, ecx
    mov r10, rdx
    mov rdx, r8
    mov r8, r9
    mov r9, [rsp + 40]

    sub rsp, 28h
    mov rax, [rsp + 48 + 28h]
    mov [rsp + 20h], rax
    mov rax, [rsp + 56 + 28h]
    mov [rsp + 28h], rax

    mov eax, ecx
    syscall
    add rsp, 28h
    ret
DirectSyscall ENDP

; Hardware Breakpoint Persistence
; Sets DR0-DR3 directly (if possible in user-mode via Context manipulation)
IL_PersistHWBP PROC
    ; Logic moved to C++ using NtSetContextThread
    ret
IL_PersistHWBP ENDP

; Syscall Hooking Detection
IL_IsSyscallHooked PROC
    mov rax, rcx
    movzx edx, byte ptr [rax]
    cmp dl, 0E9h
    jz hooked
    cmp dl, 0E8h
    jz hooked
    xor al, al
    ret
hooked:
    mov al, 1
    ret
IL_IsSyscallHooked ENDP

; Anti-Attach Patching (Inline ret)
IL_PatchAntiAttach PROC
    mov rax, rcx
    mov byte ptr [rax], 0C3h ; ret
    ret
IL_PatchAntiAttach ENDP

CheckTrapFlagInternal PROC
    pushfq
    or qword ptr [rsp], 100h
    popfq
    nop ; Triggers STATUS_SINGLE_STEP if no debugger
    ret
CheckTrapFlagInternal ENDP

CheckVMwareBackdoorInternal PROC
    push rbx
    mov eax, 56584D48h
    mov ebx, 0
    mov ecx, 10
    mov edx, 5658h
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
