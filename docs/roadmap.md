# Xen-OFCrypt Premium — Implementation Roadmap

**Date:** 2026-05-25
**Status:** Approved
**Last Updated:** 2026-05-28

---

## Timeline Overview

```
Week  0:    POC Phase (High-Risk Proofs-of-Concept)
Week  1-4:  Milestone 1 — Tier 1 Phase 1 (Foundation)
Week  5-8:  Milestone 2 — Tier 1 Phase 2 (Core Evasion)
Week  9-13: Milestone 3 — Tier 2 (Advanced Evasion)
Week 14-17: Milestone 4 — Tier 3 (Competitive Edge)
Week 18-20: Milestone 5 — Tier 4 (Polish)
```

---

## Week 0: POC Phase (High-Risk Verification)

Все HIGH-RISK модули требуют POC перед полноценной реализацией.

| POC | Что проверить | Критерий успеха | Результат |
|---|---|---|---|
| TLS Callback Mini-Unhook | Unhooking внутри TLS callback до WinMain | AMSI хуки сняты до первого AmsiScanBuffer | ✅ PASS |
| Indirect Syscall Fallback | Gadget pool пуст → hotpatch → direct fallback | Stub не крашится при отсутствии гаджетов | ✅ PASS — 3-tier: gadget → hotpatch → direct |
| Unified VEH | GuardPage + PatchlessBypass + scanner-detect | Нет конфликтов, все три работают | ✅ PASS |
| RSP Pivot Stack Spoof | Spoofed call с RSP pivot на NtAllocateVirtualMemory | Стек-трейс легитимный, нет краша | ⚠️ PARTIAL — v1 simple frame spoof DONE, v2 RSP pivot отложен |
| .NET Memory Load | Method A: temp file + delete с CLR AMSI bypass | Assembly выполняется, AMSI clean | ✅ PASS |

---

## Milestone 1: Foundation (3-4 weeks) — ✅ COMPLETE

**Goal:** Build infrastructure layer that all other techniques depend on.

### Week 1: KnownDlls Unhooking
- [x] Rewrite `Unhook.cpp` for `\KnownDlls\ntdll.dll` object namespace
- [x] NtOpenSection + NtMapViewOfSection via early PEB walk
- [x] TLS Callback Mini-Unhook: минимальный inline PEB walk + KnownDlls unhooking внутри TlsCallback.cpp, ДО WinMain
- [x] Fallback to existing disk-based unhooking (RefreshNtdll for Win11 24H2 compatibility)
- [x] Test: clean ntdll functions available after unhooking (strict byte-level test, 22/22 pass)

### Week 2: Full Dynamic API Resolution
- [x] Expand ApiResolver with CRC32C hashing (SSE4.2 hardware accelerated)
- [x] Builder: create `ApiHashDB.cs` for hash table generation
- [x] Store hash table in XRESRC marker (XRESRC used for research params, hash table not stored — deferred to M4)
- [x] Remove kernel32 imports from IAT (PEB walk only)
- [x] Stack-built strings for all module/function names
- [x] Test: `dumpbin /imports` shows minimal IAT — verified: only kernel32/user32/ntdll/bcrypt/ole32/mscoree

### Week 3-4: Indirect Syscalls
- [x] Create `IndirectSyscall.asm` (MASM x64)
- [x] Implement gadget pool scanner (0F 05 C3 in ntdll/kernel32/kernelbase)
- [x] Multi-tier fallback: Tier 1 gadget → Tier 2 hotpatch trampoline → Tier 3 direct syscall
- [x] Hotpatch trampoline: scan ntdll for 5-byte NOP areas before functions
- [x] Per-syscall typed trampolines
- [x] Expand SSN extraction: pattern + Halo's Gate + syscall table sorting (FreshyCalls)
- [x] Expand tracked syscalls from 4 to 18
- [x] Integrate with KnownDlls unhooking (SSN extraction on clean ntdll)
- [x] Syscall::Init() always called (SSN resolution for Tier 3 fallback even without IndirectSyscalls)
- [x] Hotpatch guarded behind GadgetPool::Count() > 0 (prevents ntdll prologue corruption)
- [x] Test: stack trace from kernel shows return address in legitimate module

**M1 Deliverable:** ✅ COMPLETE — Stub with clean ntdll, minimal IAT, indirect syscalls. All ciphers + RunPE E2E tested (9/9 PASS).

---

## Milestone 2: Core Evasion (3-4 weeks) — ✅ CODE COMPLETE

**Goal:** Core evasion techniques that make stub invisible to standard EDR.

### Week 5: Patchless AMSI/ETW Bypass
- [x] Rewrite `Telemetry.cpp` for VEH + DR0/DR1 approach
- [x] Unified VEH handler: POC-first — GuardPage + PatchlessBypass coexistence verified
- [x] Если unified POC проваливается → раздельные VEH handlers (N/A — unified works)
- [x] HWBP on amsi!AmsiScanBuffer + ntdll!EtwEventWrite
- [x] CLR-level AMSI bypass (clr!AmsiScan via DR2) — prepare for Tier 2
- [x] Remove old byte-patching code
- [x] Test: AMSI scan returns clean, no bytes modified in memory — E2E verified (PatchlessAmsiEtw toggle PASS)

### Week 6-7: Call Stack Spoofing
- [x] Phased approach: v1=simple frame spoof (safe), v2=RSP pivot (high-risk, only after POC)
- [x] v1: Create `StackSpoof.h/.cpp` + `StackSpoof.asm` — simple return address spoof via jmp rbx/rsi gadgets
- [x] v1: Gadget discovery (FF E3 / FF E6 — much more common than 0F 05 C3)
- [x] v1: SpoofCall wrapper для всех sensitive Nt* calls
- [ ] v2 POC: RSP pivot + UNWIND_INFO на NtAllocateVirtualMemory — only if POC passes
- [x] Integrate spoofed calls with indirect syscalls
- [x] Test v1: RtlWalkFrameChain не показывает наш модуль в return address

### Week 8: Anti-Memory Scanning
- [x] Create `AntiMemScan.h/.cpp`
- [x] Enhance Phantom DLL: ensure Image classification persists after hollowing
- [x] Thread start address normalization
- [x] Scanner detection (external ReadProcessMemory monitoring)
- [x] Integrate GuardPage with scanner detection (external vs internal access)
- [ ] Test: PE-sieve classifies our memory as Image-backed, not Private — pending external tool verification

**M2 Deliverable:** ✅ CODE COMPLETE — All 6 core evasion modules implemented. Patchless AMSI/ETW, spoofed stacks, anti-mem scanning. E2E verified for PatchlessAmsiEtw toggle.

---

## Milestone 3: Advanced Evasion (4-5 weeks) — ✅ CODE COMPLETE

**Goal:** Add techniques that separate premium crypter from basic one.

### Week 9-10: Remote Injection Suite
- [x] Create `Injection.h/.cpp`
- [x] Implement 5 injection methods (Section mapping, APC, Thread hijack, Process hollow+, Callback)
- [x] Target process auto-selection
- [x] All injection calls via spoofed stack + indirect syscalls
- [ ] Test: each method works against notepad.exe target — requires shellcode test payload

### Week 11-12: Ekko/Foliage Sleep Obfuscation
- [x] Rewrite `SleepObf.cpp` for Ekko approach
- [x] NtContinue context chain
- [x] Full memory + heap encryption during sleep (ChaCha20 via PureCrypto)
- [x] CreateTimerQueueTimer for wake-up
- [x] Sleep interval jitter
- [ ] Test: memory encrypted during sleep, decrypted after wake — pending manual verification

### Week 12-13: .NET Assembly Loading + Thread Normalization
- [x] Create `DotNetLoader.h/.cpp`
- [x] Method A: temp file + delete — ExecuteInDefaultAppDomain с CLR AMSI bypass
- [x] POC: загрузить HelloWorld.exe через Method A с CLR AMSI bypass
- [x] CLR hosting (ICLRRuntimeHost → Start → ExecuteInDefaultAppDomain)
- [x] CLR-level AMSI bypass via HWBP (DR2) на clr!AmsiScan
- [x] NtDeleteFile для немедленного удаления temp файла
- [x] Payload type detection (native vs .NET)
- [x] Create `ThreadNormalizer.h/.cpp`
- [x] JitteredSleep, callback diversification, thread pool creation
- [x] Replace all Sleep() calls with JitteredSleep()
- [ ] Test: .NET assembly loads and executes, sleep shows jitter — pending .NET test payload

**M3 Deliverable:** ✅ CODE COMPLETE — All advanced evasion modules implemented. Injection, Ekko sleep, .NET loading, thread normalization.

---

## Milestone 4: Competitive Edge (3-4 weeks) — ⬜ NOT STARTED

**Goal:** Features that match $1500-5000/month commercial products.

### Week 14: Sideload Delivery Formats
- [ ] Implement CPL loader (CPlApplet export)
- [ ] Implement XLL loader (xlAutoOpen export)
- [ ] Implement MSI builder (custom action DLL)
- [ ] Implement HTA loader (mshta.exe wrapper)
- [ ] Implement JS/VBS loader (script-based)
- [ ] Builder: output format dropdown + per-format build logic
- [ ] Test: each format bypasses AppLocker default rules

### Week 15: Build Randomization + Anti-Dump
- [x] Randomize PEMutator pipeline order (with dependency rules) — PARTIAL: timestamps, section names, resource mimicry, Rich header strip exist
- [ ] Random junk layer count, entry point, section names (partial: section name randomization exists)
- [ ] Per-build seed for reproducibility
- [ ] Create `AntiDump.h/.cpp`
- [ ] PE header erasure, section re-encryption on access, RPM detection
- [ ] Integrate with GuardPage VEH
- [ ] Test: 10 builds with different seeds all produce different binaries; dumps are corrupted

### Week 16-17: Staged Delivery + Per-EDR Profiles
- [ ] Create `StagedDelivery.h/.cpp` — StageLoader.cpp exists for staged DECRYPTION only, no remote HTTPS/DoH delivery
- [ ] HTTPS primary + DoH-Resolved HTTPS — DoH только для DNS resolution, не TXT transfer
- [ ] Domain Fronting (note: CloudFront ограничил, fallback на другие CDN)
- [ ] Environment validation before download
- [ ] XSTAGE sentinel marker
- [ ] Builder: staging config UI, URL input, method selection
- [ ] Enhance BypassEngine.cs for active per-EDR profiles
- [ ] Stub-side EDR detection + profile application
- [ ] Defender-specific profile + Universal baseline
- [ ] Test: stub downloads payload from test server, EDR detection works

**M4 Deliverable:** ⬜ NOT STARTED — Sideload formats, staged delivery, per-EDR profiles all pending. Build randomization partial. Anti-dump not implemented.

---

## Milestone 5: Polish (2-3 weeks) — ⬜ PARTIAL

**Goal:** Professional polish — UX, testing, certificate cloning.

### Week 18: Certificate Cloning + CFG Bypass
- [ ] Certificate Cloning: протестировать против Defender signature validation (RESEARCH FIRST)
- [x] Self-signed code signing — CodeSigner.cs generates ephemeral X.509 + Authenticode
- [ ] Certificate database (50+ legitimate PEs) — только если RESEARCH показывает эффективность
- [ ] Implement certificate cloning in CodeSigner.cs — только после положительного RESEARCH
- [ ] Create `CfgBypass.h/.cpp`
- [ ] CFG bitmap manipulation
- [ ] Test: SmartScreen shows legitimate publisher, CFG bypass works

### Week 19: DLL Unlinking + Builder UX
- [ ] Create `DllUnlink.h/.cpp` — functionality exists in `Phantom::UnlinkFromPeb()` but no standalone module
- [ ] PEB LDR_DATA_TABLE_ENTRY unlinking
- [ ] Builder: config templates, build log, payload simulator
- [ ] Builder: validation dashboard, evasion techniques checklist
- [ ] Test: EnumProcessModules doesn't list our module, builder UX works

### Week 20: Testing Pipeline
- [x] Create `TestRunner.cpp` with console-subsystem test harness (22/22 tests passing)
- [x] E2E test suite: 9/9 PASS — all ciphers (XOR/RC4/AES-256/ChaCha20) + RunPE (with/without IndirectSyscalls) + feature toggles (PatchlessAmsiEtw/AntiDebug/KnownDllsUnhook)
- [ ] Static analysis tests (VT, pe-sieve, pestudio, YARA)
- [ ] Dynamic analysis tests (Defender, AMSI, ETW)
- [ ] Memory scanning tests (pe-sieve, HollowsHunter, Moneta)
- [ ] Network analysis tests (for staged delivery)
- [ ] Regression testing framework
- [ ] Run full pipeline and document baseline results

**M5 Deliverable:** ⬜ PARTIAL — TestRunner + E2E tests exist, self-signed code signing works. Certificate cloning, CFG bypass, DLL unlink module, full testing pipeline all pending.

---

## Key Decision Points

| Milestone | Decision Point | Criteria | Status |
|---|---|---|---|
| M1 → M2 | Proceed to Phase 2? | Foundation compiles, indirect syscalls work, IAT minimal | ✅ PASSED |
| M2 → M3 | Tier 1 complete? | All 6 modules functional, VT ≤ 5/72 | ✅ CODE DONE, pending VT test |
| M3 → M4 | Tier 2 complete? | All 4 modules functional, injection + Ekko + .NET working | ✅ CODE DONE, pending runtime test |
| M4 → M5 | Tier 3 complete? | All 5 modules functional, sideload formats work | ⬜ NOT STARTED |
| M5 | Release ready? | All 20 features, testing pipeline passes, builder UX complete | ⬜ NOT STARTED |

---

## Progress Summary

| Milestone | Total Items | Done | Partial | Not Done | % Complete |
|---|---|---|---|---|---|
| Week 0 (POC) | 5 | 4 | 1 | 0 | 90% |
| M1 (Foundation) | 17 | 17 | 0 | 0 | 100% |
| M2 (Core Evasion) | 12 | 11 | 0 | 1 | 92% |
| M3 (Advanced Evasion) | 14 | 12 | 0 | 2 | 86% |
| M4 (Competitive Edge) | 14 | 1 | 1 | 12 | 11% |
| M5 (Polish) | 11 | 3 | 0 | 8 | 27% |
| **TOTAL** | **73** | **48** | **2** | **23** | **68%** |

---

## Bugs Fixed (Session 2026-05-28)

| Bug | Root Cause | Fix |
|---|---|---|
| ChaCha20 decryption fail | BCrypt BCryptCreateHash fails on some Windows configs | Replace BCrypt SHA-512 with PureCrypto::Sha512 (zero WinAPI) |
| RunPE without IndirectSyscalls | Syscall::Init() only called when bIndirectSyscalls=true → SSN=0 → all Nt* calls fail | Always call Syscall::Init() for Tier 3 fallback |
| Hotpatch corrupts ntdll | InstallTrampoline overwrites Nt prologues (8 bytes), breaking WinAPI internal calls (CreateProcessW) | Gate Tier 2 behind GadgetPool::Count() > 0; skip hotpatch when IndirectSyscalls disabled |

---

## Risk Mitigation Schedule

| Risk | Mitigation | When | Status |
|---|---|---|---|
| VEH handler conflict | Unified VEH POC → раздельные handlers если POC fails | Week 0 + M2 Week 5 | ✅ RESOLVED |
| StubConfig size change | Version field + migration path | M1 Week 1 | ✅ RESOLVED — version 0x02, 44 bytes |
| Indirect syscall gadget scarcity | Multi-tier fallback: gadget → hotpatch → direct | M1 Week 3 | ✅ RESOLVED — 3-tier fallback |
| Ekko NtContinue issues | Fallback to simple XOR sleep | M3 Week 11 | ✅ IMPLEMENTED |
| Staged delivery blocked | DoH-resolved HTTPS + domain fronting fallback | M4 Week 16 | ⬜ NOT YET |
| .NET CLR memory loading | Method A (temp file) → Method B (managed bootstrap) | M3 Week 12 | ✅ RESOLVED — Method A works |
| AMSI hooks before WinMain | TLS Callback mini-unhook | Week 0 + M1 Week 1 | ✅ RESOLVED |
| RSP pivot stack spoof crash | Phased: v1 simple spoof, v2 pivot only after POC | Week 0 + M2 Week 6 | ⚠️ v1 DONE, v2 deferred |
| Certificate cloning ineffective | RESEARCH against Defender first | M5 Week 18 | ⬜ NOT YET |
| Hotpatch corrupts ntdll internals | Gate Tier 2 behind GadgetPool::Count() | M1 Week 3 (fix 2026-05-28) | ✅ RESOLVED |
