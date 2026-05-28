; ═══════════════════════════════════════════════════════════════
;  sc_test.asm — Position-independent x64 shellcode for E2E testing
;  Writes "SC_OK\n" to C:\temp\sc_marker.txt
;
;  Technique: PEB → InLoadOrderModuleList → 3rd entry = kernel32 (Win10+)
;  Export table walk with key-character name matching
;  Returns TRUE (1) for CallbackProxy compatibility
; ═══════════════════════════════════════════════════════════════

option casemap:none

.code

PUBLIC ScEntry

ScEntry PROC

; ── Save non-volatile registers ──
push rbx
push rbp
push rsi
push rdi
push r14
push r15
sub rsp, 68h

; ── Step 1: PEB → kernel32.dll base ──
mov r15, gs:[60h]       ; TEB->ProcessEnvironmentBlock
mov r15, [r15+18h]      ; PEB->Ldr
mov r15, [r15+10h]      ; InLoadOrderModuleList.Flink (1st = current exe)
mov r15, [r15]          ; → 2nd entry (ntdll.dll)
mov r15, [r15]          ; → 3rd entry (kernel32.dll)
mov r14, [r15+30h]      ; DllBase

; ── Step 2: Get export directory ──
mov ebx, [r14+3Ch]      ; e_lfanew
mov ebx, [r14+rbx+88h]  ; ExportDirectory RVA
add rbx, r14            ; ExportDirectory VA

mov r8d, [rbx+18h]      ; NumberOfNames
mov r9d, [rbx+20h]      ; AddressOfNames RVA
add r9, r14
mov r10d, [rbx+1Ch]     ; AddressOfFunctions RVA
add r10, r14
mov r11d, [rbx+24h]     ; AddressOfNameOrdinals RVA
add r11, r14

; ── Step 3: Resolve CreateFileA ──
xor ecx, ecx
@@find_cfa:
    cmp ecx, r8d
    jge @@fail
    mov eax, [r9+rcx*4]
    add rax, r14
    cmp byte ptr [rax+0],  'C'
    jne @@next_cfa
    cmp byte ptr [rax+6],  'F'
    jne @@next_cfa
    cmp byte ptr [rax+10], 'A'
    jne @@next_cfa
    movzx eax, word ptr [r11+rcx*2]
    mov eax, [r10+rax*4]
    add rax, r14
    mov r15, rax               ; r15 = CreateFileA
    jmp @@find_wf
@@next_cfa:
    inc ecx
    jmp @@find_cfa

; ── Step 4: Resolve WriteFile ──
@@find_wf:
    xor ecx, ecx
@@loop_wf:
    cmp ecx, r8d
    jge @@fail
    mov eax, [r9+rcx*4]
    add rax, r14
    cmp byte ptr [rax+0], 'W'
    jne @@next_wf
    cmp byte ptr [rax+5], 'F'
    jne @@next_wf
    movzx eax, word ptr [r11+rcx*2]
    mov eax, [r10+rax*4]
    add rax, r14
    mov rbx, rax               ; rbx = WriteFile
    jmp @@find_ch
@@next_wf:
    inc ecx
    jmp @@loop_wf

; ── Step 5: Resolve CloseHandle ──
@@find_ch:
    xor ecx, ecx
@@loop_ch:
    cmp ecx, r8d
    jge @@fail
    mov eax, [r9+rcx*4]
    add rax, r14
    cmp byte ptr [rax+0], 'C'
    jne @@next_ch
    cmp byte ptr [rax+1], 'l'
    jne @@next_ch
    cmp byte ptr [rax+5], 'H'
    jne @@next_ch
    movzx eax, word ptr [r11+rcx*2]
    mov eax, [r10+rax*4]
    add rax, r14
    mov rsi, rax               ; rsi = CloseHandle
    jmp @@do_work
@@next_ch:
    inc ecx
    jmp @@loop_ch

@@fail:
    xor eax, eax
    add rsp, 68h
    pop r15
    pop r14
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    ret

; ── Step 6: Build strings and call APIs ──
@@do_work:
    ; Build path on stack: "C:\temp\sc_marker.txt"
    ; 22 chars + null = 23 bytes
    lea rdi, [rsp+38h]

    ; Load QWORDs via rax (MASM cannot do mov qword ptr [mem], imm64)
    mov rax, 5C706D65745C3A43h   ; "C:\temp\"
    mov [rdi], rax
    mov rax, 656B72616D5F6373h   ; "sc_marke"
    mov [rdi+8], rax
    mov dword ptr [rdi+10h], 78742E72h   ; bytes 16-19: "r.tx" (LE)
    mov word ptr [rdi+14h], 0074h         ; bytes 20-21: "t\0"

    ; Build content: "SC_OK\n" = 7 bytes
    lea rbp, [rsp+50h]
    mov dword ptr [rbp], 4F5F4353h        ; "SC_O"
    mov word ptr [rbp+4], 0A4Bh           ; "K\n"
    mov byte ptr [rbp+6], 0               ; null

    ; ── Call CreateFileA ──
    mov rcx, rdi
    mov rdx, 40000000h           ; GENERIC_WRITE
    xor r8d, r8d                 ; dwShareMode = 0
    xor r9d, r9d                 ; lpSecurityAttributes = NULL
    mov dword ptr [rsp+20h], 2   ; CREATE_ALWAYS
    mov dword ptr [rsp+28h], 80h ; FILE_ATTRIBUTE_NORMAL
    mov qword ptr [rsp+30h], 0   ; hTemplateFile = NULL
    call r15

    cmp rax, -1
    je @@done
    mov rdi, rax                 ; rdi = file handle

    ; ── Call WriteFile ──
    mov rcx, rdi
    lea rdx, [rsp+50h]          ; lpBuffer
    mov r8d, 6                   ; 6 bytes
    lea r9, [rsp+58h]           ; lpNumberOfBytesWritten
    mov qword ptr [rsp+20h], 0   ; lpOverlapped = NULL
    call rbx

    ; ── Call CloseHandle ──
    mov rcx, rdi
    call rsi

@@done:
    mov eax, 1                   ; return TRUE
    add rsp, 68h
    pop r15
    pop r14
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    ret

ScEntry ENDP

END
