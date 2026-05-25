;
;  IndirectSyscall.asm — MASM x64
;  Per-syscall typed trampolines for indirect and direct syscalls
;
;  Design:
;    Tier 1 (_I suffix): Indirect via gadget — loads SSN, JMPs to 0F 05 C3 gadget
;    Tier 2:            Hotpatch — handled in C++ (function pointer call)
;    Tier 3 (_D suffix): Direct syscall — loads SSN, does syscall; ret
;
;  Each trampoline matches the exact calling convention of the Nt function.
;  The stack frame is naturally correct because no extra params are injected.
;  SSN and gadget addresses come from global tables populated by C++ Init().
;

.DATA

; ═══════════════════════════════════════════════════════════
;  Global tables — populated by Syscall::Init() at runtime
;  Each entry: 8 bytes (low DWORD = SSN for SyscallTable,
;                       QWORD = gadget addr for GadgetTable)
; ═══════════════════════════════════════════════════════════
ALIGN 16
PUBLIC SyscallTable
SyscallTable DQ 18 DUP(0)

ALIGN 16
PUBLIC GadgetTable
GadgetTable DQ 18 DUP(0)

; ═══════════════════════════════════════════════════════════
;  Entry index constants — must match Syscall.cpp enum order
; ═══════════════════════════════════════════════════════════
IDX_NtAllocateVirtualMemory   = 0
IDX_NtProtectVirtualMemory    = 1
IDX_NtWriteVirtualMemory      = 2
IDX_NtCreateThreadEx          = 3
IDX_NtOpenProcess             = 4
IDX_NtOpenThread              = 5
IDX_NtSuspendThread           = 6
IDX_NtResumeThread            = 7
IDX_NtQueueApcThread          = 8
IDX_NtContinue                = 9
IDX_NtGetContextThread        = 10
IDX_NtSetContextThread        = 11
IDX_NtClose                   = 12
IDX_NtDeleteFile              = 13
IDX_NtCreateSection           = 14
IDX_NtMapViewOfSection        = 15
IDX_NtUnmapViewOfSection      = 16
IDX_NtReadVirtualMemory       = 17

.CODE

; ═══════════════════════════════════════════════════════════
;  Tier 1: Indirect syscall trampolines (gadget-based)
;
;  Each trampoline:
;    1. mov r10, rcx  — save 1st arg (Windows syscall convention)
;    2. mov eax, SSN  — load syscall number from global table
;    3. jmp [gadget]  — jump to 0F 05 C3 in trusted module
;
;  The gadget does: syscall; ret
;  ret returns to the C++ caller (correct stack frame).
; ═══════════════════════════════════════════════════════════

NtAllocateVirtualMemory_I PROC PUBLIC
    mov r10, rcx
    mov eax, dword ptr [SyscallTable + IDX_NtAllocateVirtualMemory * 8]
    jmp qword ptr [GadgetTable + IDX_NtAllocateVirtualMemory * 8]
NtAllocateVirtualMemory_I ENDP

NtProtectVirtualMemory_I PROC PUBLIC
    mov r10, rcx
    mov eax, dword ptr [SyscallTable + IDX_NtProtectVirtualMemory * 8]
    jmp qword ptr [GadgetTable + IDX_NtProtectVirtualMemory * 8]
NtProtectVirtualMemory_I ENDP

NtWriteVirtualMemory_I PROC PUBLIC
    mov r10, rcx
    mov eax, dword ptr [SyscallTable + IDX_NtWriteVirtualMemory * 8]
    jmp qword ptr [GadgetTable + IDX_NtWriteVirtualMemory * 8]
NtWriteVirtualMemory_I ENDP

NtCreateThreadEx_I PROC PUBLIC
    mov r10, rcx
    mov eax, dword ptr [SyscallTable + IDX_NtCreateThreadEx * 8]
    jmp qword ptr [GadgetTable + IDX_NtCreateThreadEx * 8]
NtCreateThreadEx_I ENDP

NtOpenProcess_I PROC PUBLIC
    mov r10, rcx
    mov eax, dword ptr [SyscallTable + IDX_NtOpenProcess * 8]
    jmp qword ptr [GadgetTable + IDX_NtOpenProcess * 8]
NtOpenProcess_I ENDP

NtOpenThread_I PROC PUBLIC
    mov r10, rcx
    mov eax, dword ptr [SyscallTable + IDX_NtOpenThread * 8]
    jmp qword ptr [GadgetTable + IDX_NtOpenThread * 8]
NtOpenThread_I ENDP

NtSuspendThread_I PROC PUBLIC
    mov r10, rcx
    mov eax, dword ptr [SyscallTable + IDX_NtSuspendThread * 8]
    jmp qword ptr [GadgetTable + IDX_NtSuspendThread * 8]
NtSuspendThread_I ENDP

NtResumeThread_I PROC PUBLIC
    mov r10, rcx
    mov eax, dword ptr [SyscallTable + IDX_NtResumeThread * 8]
    jmp qword ptr [GadgetTable + IDX_NtResumeThread * 8]
NtResumeThread_I ENDP

NtQueueApcThread_I PROC PUBLIC
    mov r10, rcx
    mov eax, dword ptr [SyscallTable + IDX_NtQueueApcThread * 8]
    jmp qword ptr [GadgetTable + IDX_NtQueueApcThread * 8]
NtQueueApcThread_I ENDP

NtContinue_I PROC PUBLIC
    mov r10, rcx
    mov eax, dword ptr [SyscallTable + IDX_NtContinue * 8]
    jmp qword ptr [GadgetTable + IDX_NtContinue * 8]
NtContinue_I ENDP

NtGetContextThread_I PROC PUBLIC
    mov r10, rcx
    mov eax, dword ptr [SyscallTable + IDX_NtGetContextThread * 8]
    jmp qword ptr [GadgetTable + IDX_NtGetContextThread * 8]
NtGetContextThread_I ENDP

NtSetContextThread_I PROC PUBLIC
    mov r10, rcx
    mov eax, dword ptr [SyscallTable + IDX_NtSetContextThread * 8]
    jmp qword ptr [GadgetTable + IDX_NtSetContextThread * 8]
NtSetContextThread_I ENDP

NtClose_I PROC PUBLIC
    mov r10, rcx
    mov eax, dword ptr [SyscallTable + IDX_NtClose * 8]
    jmp qword ptr [GadgetTable + IDX_NtClose * 8]
NtClose_I ENDP

NtDeleteFile_I PROC PUBLIC
    mov r10, rcx
    mov eax, dword ptr [SyscallTable + IDX_NtDeleteFile * 8]
    jmp qword ptr [GadgetTable + IDX_NtDeleteFile * 8]
NtDeleteFile_I ENDP

NtCreateSection_I PROC PUBLIC
    mov r10, rcx
    mov eax, dword ptr [SyscallTable + IDX_NtCreateSection * 8]
    jmp qword ptr [GadgetTable + IDX_NtCreateSection * 8]
NtCreateSection_I ENDP

NtMapViewOfSection_I PROC PUBLIC
    mov r10, rcx
    mov eax, dword ptr [SyscallTable + IDX_NtMapViewOfSection * 8]
    jmp qword ptr [GadgetTable + IDX_NtMapViewOfSection * 8]
NtMapViewOfSection_I ENDP

NtUnmapViewOfSection_I PROC PUBLIC
    mov r10, rcx
    mov eax, dword ptr [SyscallTable + IDX_NtUnmapViewOfSection * 8]
    jmp qword ptr [GadgetTable + IDX_NtUnmapViewOfSection * 8]
NtUnmapViewOfSection_I ENDP

NtReadVirtualMemory_I PROC PUBLIC
    mov r10, rcx
    mov eax, dword ptr [SyscallTable + IDX_NtReadVirtualMemory * 8]
    jmp qword ptr [GadgetTable + IDX_NtReadVirtualMemory * 8]
NtReadVirtualMemory_I ENDP


; ═══════════════════════════════════════════════════════════
;  Tier 3: Direct syscall trampolines (no gadget/hotpatch)
;
;  WARNING: Return address on kernel stack points to our module,
;  not ntdll. EDR may detect this via call-stack analysis.
;  Only used as last resort when Tier 1 and Tier 2 are unavailable.
; ═══════════════════════════════════════════════════════════

NtAllocateVirtualMemory_D PROC PUBLIC
    mov r10, rcx
    mov eax, dword ptr [SyscallTable + IDX_NtAllocateVirtualMemory * 8]
    syscall
    ret
NtAllocateVirtualMemory_D ENDP

NtProtectVirtualMemory_D PROC PUBLIC
    mov r10, rcx
    mov eax, dword ptr [SyscallTable + IDX_NtProtectVirtualMemory * 8]
    syscall
    ret
NtProtectVirtualMemory_D ENDP

NtWriteVirtualMemory_D PROC PUBLIC
    mov r10, rcx
    mov eax, dword ptr [SyscallTable + IDX_NtWriteVirtualMemory * 8]
    syscall
    ret
NtWriteVirtualMemory_D ENDP

NtCreateThreadEx_D PROC PUBLIC
    mov r10, rcx
    mov eax, dword ptr [SyscallTable + IDX_NtCreateThreadEx * 8]
    syscall
    ret
NtCreateThreadEx_D ENDP

NtOpenProcess_D PROC PUBLIC
    mov r10, rcx
    mov eax, dword ptr [SyscallTable + IDX_NtOpenProcess * 8]
    syscall
    ret
NtOpenProcess_D ENDP

NtOpenThread_D PROC PUBLIC
    mov r10, rcx
    mov eax, dword ptr [SyscallTable + IDX_NtOpenThread * 8]
    syscall
    ret
NtOpenThread_D ENDP

NtSuspendThread_D PROC PUBLIC
    mov r10, rcx
    mov eax, dword ptr [SyscallTable + IDX_NtSuspendThread * 8]
    syscall
    ret
NtSuspendThread_D ENDP

NtResumeThread_D PROC PUBLIC
    mov r10, rcx
    mov eax, dword ptr [SyscallTable + IDX_NtResumeThread * 8]
    syscall
    ret
NtResumeThread_D ENDP

NtQueueApcThread_D PROC PUBLIC
    mov r10, rcx
    mov eax, dword ptr [SyscallTable + IDX_NtQueueApcThread * 8]
    syscall
    ret
NtQueueApcThread_D ENDP

NtContinue_D PROC PUBLIC
    mov r10, rcx
    mov eax, dword ptr [SyscallTable + IDX_NtContinue * 8]
    syscall
    ret
NtContinue_D ENDP

NtGetContextThread_D PROC PUBLIC
    mov r10, rcx
    mov eax, dword ptr [SyscallTable + IDX_NtGetContextThread * 8]
    syscall
    ret
NtGetContextThread_D ENDP

NtSetContextThread_D PROC PUBLIC
    mov r10, rcx
    mov eax, dword ptr [SyscallTable + IDX_NtSetContextThread * 8]
    syscall
    ret
NtSetContextThread_D ENDP

NtClose_D PROC PUBLIC
    mov r10, rcx
    mov eax, dword ptr [SyscallTable + IDX_NtClose * 8]
    syscall
    ret
NtClose_D ENDP

NtDeleteFile_D PROC PUBLIC
    mov r10, rcx
    mov eax, dword ptr [SyscallTable + IDX_NtDeleteFile * 8]
    syscall
    ret
NtDeleteFile_D ENDP

NtCreateSection_D PROC PUBLIC
    mov r10, rcx
    mov eax, dword ptr [SyscallTable + IDX_NtCreateSection * 8]
    syscall
    ret
NtCreateSection_D ENDP

NtMapViewOfSection_D PROC PUBLIC
    mov r10, rcx
    mov eax, dword ptr [SyscallTable + IDX_NtMapViewOfSection * 8]
    syscall
    ret
NtMapViewOfSection_D ENDP

NtUnmapViewOfSection_D PROC PUBLIC
    mov r10, rcx
    mov eax, dword ptr [SyscallTable + IDX_NtUnmapViewOfSection * 8]
    syscall
    ret
NtUnmapViewOfSection_D ENDP

NtReadVirtualMemory_D PROC PUBLIC
    mov r10, rcx
    mov eax, dword ptr [SyscallTable + IDX_NtReadVirtualMemory * 8]
    syscall
    ret
NtReadVirtualMemory_D ENDP

END
