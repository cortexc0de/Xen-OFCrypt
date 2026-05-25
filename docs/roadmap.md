# Xen-OFCrypt Premium — Implementation Roadmap

**Date:** 2026-05-25
**Status:** Approved

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

| POC | Что проверить | Критерий успеха | Результат при провале |
|---|---|---|---|
| TLS Callback Mini-Unhook | Unhooking внутри TLS callback до WinMain | AMSI хуки сняты до первого AmsiScanBuffer | Переносим unhooking в самое начало WinMain |
| Indirect Syscall Fallback | Gadget pool пуст → hotpatch → direct fallback | Stub не крашится при отсутствии гаджетов | Остаёмся на direct syscalls |
| Unified VEH | GuardPage + PatchlessBypass + scanner-detect | Нет конфликтов, все три работают | Раздельные VEH handlers |
| RSP Pivot Stack Spoof | Spoofed call с RSP pivot на NtAllocateVirtualMemory | Стек-трейс легитимный, нет краша | Остаёмся на v1 (simple frame spoof) |
| .NET Memory Load | Method A: temp file + delete с CLR AMSI bypass | Assembly выполняется, AMSI clean | Откладываем .NET loading |

---

## Milestone 1: Foundation (3-4 weeks)

**Goal:** Build infrastructure layer that all other techniques depend on.

### Week 1: KnownDlls Unhooking
- [ ] Rewrite `Unhook.cpp` for `\KnownDlls\ntdll.dll` object namespace
- [ ] NtOpenSection + NtMapViewOfSection via early PEB walk
- [ ] **TLS Callback Mini-Unhook (ПРОБЛЕМА #1):** минимальный inline PEB walk + KnownDlls unhooking внутри TlsCallback.cpp, ДО WinMain
- [ ] Fallback to existing disk-based unhooking
- [ ] Test: clean ntdll functions available after unhooking

### Week 2: Full Dynamic API Resolution
- [ ] Expand ApiResolver with CRC32C hashing (SSE4.2 hardware accelerated)
- [ ] Builder: create `ApiHashDB.cs` for hash table generation
- [ ] Store hash table in XRESRC marker
- [ ] Remove kernel32 imports from IAT (PEB walk only)
- [ ] Stack-built strings for all module/function names
- [ ] Test: `dumpbin /imports` shows minimal IAT

### Week 3-4: Indirect Syscalls
- [ ] Create `IndirectSyscall.asm` (MASM x64)
- [ ] Implement gadget pool scanner (0F 05 C3 in ntdll/kernel32/kernelbase)
- [ ] **Multi-tier fallback (ПРОБЛЕМА #2):** Tier 1 gadget → Tier 2 hotpatch trampoline → Tier 3 direct syscall
- [ ] Hotpatch trampoline: scan ntdll for 5-byte NOP areas before functions
- [ ] Per-syscall typed trampolines
- [ ] Expand SSN extraction: pattern + Halo's Gate + syscall table sorting
- [ ] Expand tracked syscalls from 4 to ~15-20
- [ ] Integrate with KnownDlls unhooking (SSN extraction on clean ntdll)
- [ ] Test: stack trace from kernel shows return address in legitimate module

**M1 Deliverable:** Stub with clean ntdll, minimal IAT, indirect syscalls. Compiles and runs. Detection baseline established.

---

## Milestone 2: Core Evasion (3-4 weeks)

**Goal:** Core evasion techniques that make stub invisible to standard EDR.

### Week 5: Patchless AMSI/ETW Bypass
- [ ] Rewrite `Telemetry.cpp` for VEH + DR0/DR1 approach
- [ ] **Unified VEH handler (ПРОБЛЕМА #8):** POC-first — тестировать GuardPage + PatchlessBypass coexistence
- [ ] Если unified POC проваливается → раздельные VEH handlers с EXCEPTION_CONTINUE_SEARCH
- [ ] HWBP on amsi!AmsiScanBuffer + ntdll!EtwEventWrite
- [ ] CLR-level AMSI bypass (clr!AmsiScan via DR2) — prepare for Tier 2
- [ ] Remove old byte-patching code
- [ ] Test: AMSI scan returns clean, no bytes modified in memory

### Week 6-7: Call Stack Spoofing
- [ ] **Phased approach (ПРОБЛЕМА #3):** v1=simple frame spoof (safe), v2=RSP pivot (high-risk, only after POC)
- [ ] v1: Create `StackSpoof.h/.cpp` + `StackSpoof.asm` — simple return address spoof via jmp rbx/rsi gadgets
- [ ] v1: Gadget discovery (FF E3 / FF E6 — much more common than 0F 05 C3)
- [ ] v1: SpoofCall wrapper для всех sensitive Nt* calls
- [ ] v2 POC: RSP pivot + UNWIND_INFO на NtAllocateVirtualMemory — только если POC проходит
- [ ] Integrate spoofed calls with indirect syscalls
- [ ] Test v1: RtlWalkFrameChain не показывает наш модуль в return address

### Week 8: Anti-Memory Scanning
- [ ] Create `AntiMemScan.h/.cpp`
- [ ] Enhance Phantom DLL: ensure Image classification persists after hollowing
- [ ] Thread start address normalization
- [ ] Scanner detection (external ReadProcessMemory monitoring)
- [ ] Integrate GuardPage with scanner detection (external vs internal access)
- [ ] Test: PE-sieve classifies our memory as Image-backed, not Private

**M2 Deliverable:** Full Tier 1 crypter. Patchless AMSI/ETW, spoofed stacks, anti-mem scanning. Detection target ≤ 5/72 on VT.

---

## Milestone 3: Advanced Evasion (4-5 weeks)

**Goal:** Add techniques that separate premium crypter from basic one.

### Week 9-10: Remote Injection Suite
- [ ] Create `Injection.h/.cpp`
- [ ] Implement 5 injection methods (Section mapping, APC, Thread hijack, Process hollow+, Callback)
- [ ] Target process auto-selection
- [ ] All injection calls via spoofed stack + indirect syscalls
- [ ] Test: each method works against notepad.exe target

### Week 11-12: Ekko/Foliage Sleep Obfuscation
- [ ] Rewrite `SleepObf.cpp` for Ekko approach
- [ ] NtContinue context chain
- [ ] Full memory + heap encryption during sleep (ChaCha20 via PureCrypto)
- [ ] CreateTimerQueueTimer for wake-up
- [ ] Sleep interval jitter
- [ ] Test: memory encrypted during sleep, decrypted after wake

### Week 12-13: .NET Assembly Loading + Thread Normalization
- [ ] Create `DotNetLoader.h/.cpp`
- [ ] **Method A: temp file + delete (ПРОБЛЕМА #4):** ExecuteInDefaultAppDomain требует файл на диске
- [ ] POC: загрузить HelloWorld.exe через Method A с CLR AMSI bypass
- [ ] CLR hosting (ICLRRuntimeHost → Start → ExecuteInDefaultAppDomain)
- [ ] CLR-level AMSI bypass via HWBP (DR2) на clr!AmsiScan
- [ ] NtDeleteFile для немедленного удаления temp файла
- [ ] Payload type detection (native vs .NET)
- [ ] Если POC проваливается → откладываем .NET loading, фокус на Thread Normalization
- [ ] Create `ThreadNormalizer.h/.cpp`
- [ ] JitteredSleep, callback diversification, thread pool creation
- [ ] Replace all Sleep() calls with JitteredSleep()
- [ ] Test: .NET assembly loads and executes (if POC passes), sleep shows jitter

**M3 Deliverable:** Premium crypter with injection, sleep obfuscation, .NET loading, thread normalization.

---

## Milestone 4: Competitive Edge (3-4 weeks)

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
- [ ] Randomize PEMutator pipeline order (with dependency rules)
- [ ] Random junk layer count, entry point, section names
- [ ] Per-build seed for reproducibility
- [ ] Create `AntiDump.h/.cpp`
- [ ] PE header erasure, section re-encryption on access, RPM detection
- [ ] Integrate with GuardPage VEH
- [ ] Test: 10 builds with different seeds all produce different binaries; dumps are corrupted

### Week 16-17: Staged Delivery + Per-EDR Profiles
- [ ] Create `StagedDelivery.h/.cpp`
- [ ] HTTPS primary + **DoH-Resolved HTTPS (ПРОБЛЕМА #5 — исправлено)** — DoH только для DNS resolution, не TXT transfer
- [ ] Domain Fronting (note: CloudFront ограничил, fallback на другие CDN)
- [ ] Environment validation before download
- [ ] XSTAGE sentinel marker
- [ ] Builder: staging config UI, URL input, method selection
- [ ] Enhance BypassEngine.cs for active per-EDR profiles
- [ ] Stub-side EDR detection + profile application
- [ ] Defender-specific profile + Universal baseline
- [ ] Test: stub downloads payload from test server, EDR detection works

**M4 Deliverable:** Full-featured crypter. All sideload formats, randomization, anti-dump, staged delivery, EDR profiles.

---

## Milestone 5: Polish (2-3 weeks)

**Goal:** Professional polish — UX, testing, certificate cloning.

### Week 18: Certificate Cloning + CFG Bypass
- [ ] **Certificate Cloning (ПРОБЛЕМА #6 — RESEARCH FIRST):** протестировать против Defender signature validation
- [ ] Если Defender детектирует cloned signature → понизить до optional, не тратить время
- [ ] Certificate database (50+ legitimate PEs) — только если RESEARCH показывает эффективность
- [ ] Implement in CodeSigner.cs — только после положительного RESEARCH
- [ ] Create `CfgBypass.h/.cpp`
- [ ] CFG bitmap manipulation
- [ ] Test: SmartScreen shows legitimate publisher, CFG bypass works

### Week 19: DLL Unlinking + Builder UX
- [ ] Create `DllUnlink.h/.cpp`
- [ ] PEB LDR_DATA_TABLE_ENTRY unlinking
- [ ] Builder: config templates, build log, payload simulator
- [ ] Builder: validation dashboard, evasion techniques checklist
- [ ] Test: EnumProcessModules doesn't list our module, builder UX works

### Week 20: Testing Pipeline
- [ ] Create `tests/` directory with PowerShell test runner
- [ ] Static analysis tests (VT, pe-sieve, pestudio, YARA)
- [ ] Dynamic analysis tests (Defender, AMSI, ETW)
- [ ] Memory scanning tests (pe-sieve, HollowsHunter, Moneta)
- [ ] Network analysis tests (for staged delivery)
- [ ] Regression testing framework
- [ ] Run full pipeline and document baseline results

**M5 Deliverable:** Production-grade crypter. All 20 features implemented. Testing pipeline operational. Ready for release.

---

## Key Decision Points

| Milestone | Decision Point | Criteria |
|---|---|---|
| M1 → M2 | Proceed to Phase 2? | Foundation compiles, indirect syscalls work, IAT minimal |
| M2 → M3 | Tier 1 complete? | All 6 modules functional, VT ≤ 5/72 |
| M3 → M4 | Tier 2 complete? | All 4 modules functional, injection + Ekko + .NET working |
| M4 → M5 | Tier 3 complete? | All 5 modules functional, sideload formats work |
| M5 | Release ready? | All 20 features, testing pipeline passes, builder UX complete |

---

## Risk Mitigation Schedule

| Risk | Mitigation | When |
|---|---|---|
| VEH handler conflict | Unified VEH POC → раздельные handlers если POC fails | Week 0 + M2 Week 5 |
| StubConfig size change | Version field + migration path | M1 Week 1 |
| Indirect syscall gadget scarcity | Multi-tier fallback: gadget → hotpatch → direct | M1 Week 3 |
| Ekko NtContinue issues | Fallback to simple XOR sleep | M3 Week 11 |
| Staged delivery blocked | DoH-resolved HTTPS + domain fronting fallback | M4 Week 16 |
| .NET CLR memory loading | Method A (temp file) → Method B (managed bootstrap) | M3 Week 12 |
| AMSI hooks before WinMain | TLS Callback mini-unhook | Week 0 + M1 Week 1 |
| RSP pivot stack spoof crash | Phased: v1 simple spoof, v2 pivot only after POC | Week 0 + M2 Week 6 |
| Certificate cloning ineffective | RESEARCH against Defender first | M5 Week 18 |
