# Xen-OFCrypt Premium Crypter — Master Design Document

**Date:** 2026-05-25
**Status:** Approved
**Target:** Upgrade open-source Xen-OFCrypt to production-grade paid crypter ($1500-5000/month tier)

---

## 1. Architectural Decisions

| Decision | Choice | Rationale |
|---|---|---|
| Stub language | C++ (MSVC) + x64 MASM | Proven, max control, inline ASM for trampolines |
| Builder language | C# WPF (as-is) | Evolution, not rewrite |
| Builder-Stub bridge | Sentinel markers (.xthrx section) | Existing XCONFIG/XKEYBLK/XPAYLOD/XRESRC mechanism |
| Target architecture | x64 only | Modern standard, half the ASM work |
| Implementation approach | Modular-incremental (Approach A) | Each module = separate branch, testable in isolation |
| Payload delivery | Staged (no size limit) | Stub downloads payload from remote after environment check |
| EDR profiles | Defender for Endpoint + Universal baseline | Tier 3 adds per-product tuning |
| Implementation order | Tier 1 → 2 → 3 → 4 | Foundation-first, dependencies respected |

---

## 2. Complete Feature Catalog (20 Items)

### TIER 1 — MUST HAVE (6 items)

| # | Feature | Current State | Target |
|---|---|---|---|
| 1 | KnownDlls Unhooking | Disk-based ntdll remap (Unhook.cpp) | `\KnownDlls\ntdll.dll` object namespace, NtOpenSection + SEC_IMAGE |
| 2 | Full Dynamic API Resolution | DJB2 PEB walk, 28 hashes, 3 modules (ApiResolver.cpp) | IAT clean (ntdll basic only), PEB walk + CRC32C/djb2, stack-built strings, builder-side hash generation |
| 3 | Indirect Syscalls | Direct syscalls via pattern+Halo's Gate (Syscall.cpp) | Custom ASM trampolines + gadget pool (0F 05 C3), multi-tier fallback: indirect → hotpatch trampoline → direct syscall |
| 4 | Patchless AMSI/ETW Bypass | Byte-patching AmsiScanBuffer/EtwEventWrite (Telemetry.cpp) | VEH + DR0/DR1 hardware breakpoints, zero bytes modified, CLR-level AMSI |
| 5 | Call Stack Spoofing | Not implemented | Phased: v1=simple frame spoof (gadget return addr), v2=RSP pivot+UNWIND_INFO (high-risk POC first) |
| 6 | Anti-Memory Scanning | Partial: Phantom DLL hollowing, GuardPage, ModuleStomp | Full: Image-backed Phantom DLL, thread origin normalization, Image vs Private classification, PE-sieve/HollowsHunter/Moneta evasion |

### TIER 2 — STRONG ADVANTAGE (4 items)

| # | Feature | Current State | Target |
|---|---|---|---|
| 7 | Remote Injection Suite | RunPE + ModuleStomp + CallbackProxy (GodMode.cpp) | 5+ methods: NtCreateSection+NtMapViewOfSection, APC injection, Thread Hijacking, Process Hollowing+, CALLBACK enum-based |
| 8 | Ekko/Foliage Sleep Obfuscation | Simple XOR during Sleep, 8s default (SleepObf.cpp) | NtContinue context chain, full memory+heap encryption, RC4/ChaCha20 keying, CreateTimerQueueTimer for wake |
| 9 | .NET Assembly Loading | Not implemented | CLR hosting + custom AssemblyResolve for memory loading, clr.dll!AmsiScan HWBP bypass |
| 10 | Thread Behavior Normalization | ThreadPool only (ThreadPool.cpp) | Jitter on sleep intervals, diversified callback types, ThreadPool + Timer + APC + WSA, anti-beaconing heuristics |

### TIER 3 — COMPETITIVE EDGE (5 items)

| # | Feature | Current State | Target |
|---|---|---|---|
| 11 | Sideload Delivery Formats | EXE only | CPL, XLL, MSI, HTA, JScript/VBS — each a separate Application Whitelisting bypass |
| 12 | Build Randomization Engine | PEMutator 18-layer pipeline (fixed order) | Randomized mutation stage order, variable junk layer count, randomized entry point, per-build unique structure |
| 13 | Anti-Dump Enhancement | Guard Page + VEH only | Anti-dump: erase PE headers, re-encrypt sections on access, detect ReadProcessMemory probing |
| 14 | Staged Payload Delivery | Inline only (XPAYLOD max 512KB) | HTTPS primary + DoH-resolved HTTPS (not TXT records) + domain fronting, environment validation before download |
| 15 | Per-EDR Countermeasure Profiles | AvDatabase 25+ profiles (display only) | Active: BypassEngine generates technique selection per EDR, Defender-specific + Universal baseline |

### TIER 4 — NICE TO HAVE (5 items)

| # | Feature | Current State | Target |
|---|---|---|---|
| 16 | Certificate Cloning | Ephemeral RSA-2048 self-signed (CodeSigner.cs) | Clone cert from legitimate PE — RESEARCH: modern EDR validates signature integrity, effectiveness declining |
| 17 | CFG Bypass | Not implemented | SetValidTargetsCfgForModule or __guard_dispatch_icall_fptr manipulation |
| 18 | DLL Notification Unlinking | Not implemented | LDR_MODULE unlink from PEB LoaderEntry, InMemoryOrderModuleList removal |
| 19 | Builder UX Improvements | Functional WPF but basic | Real-time preview, config templates, build log, payload simulator |
| 20 | Private Sandbox Testing Pipeline | None | Automated testing against Defender/pe-sieve/HollowsHunter, CI-like regression |

---

## 3. Dependency Graph

### Tier 1 Internal Dependencies

```
Phase 1 — Foundation:
  KnownDlls Unhooking ──┐
  Full Dynamic API ─────┤──→ Phase 2 depends on all three
  Indirect Syscalls ────┘

Phase 2 — Core Evasion:
  Patchless AMSI/ETW ──── depends on KnownDlls Unhooking (#1)
  Call Stack Spoofing ─── depends on Indirect Syscalls (#3)
  Anti-Memory Scanning ── depends on KnownDlls (#1) + Stack Spoofing (#5)
```

### Cross-Tier Dependencies

```
Tier 2 Remote Injection (#7)  ←── Tier 1 Stack Spoofing (#5) + Indirect Syscalls (#3)
Tier 2 Ekko Sleep (#8)        ←── Tier 1 Indirect Syscalls (#3)
Tier 2 Thread Normalization (#10) ←── Tier 1 Anti-Memory Scanning (#6)
Tier 3 Staged Delivery (#14)  ←── Tier 2 Ekko Sleep (#8)
Tier 3 Per-EDR Profiles (#15) ←── Tier 1 Dynamic API (#2) + Patchless AMSI/ETW (#4)
```

---

## 4. Implementation Roadmap

| Milestone | Scope | Estimated Effort |
|---|---|---|
| M1: Foundation | Tier 1 Phase 1 (#1-3) | 3-4 weeks |
| M2: Core Evasion | Tier 1 Phase 2 (#4-6) | 3-4 weeks |
| M3: Advanced Evasion | Tier 2 (#7-10) | 4-5 weeks |
| M4: Competitive Edge | Tier 3 (#11-15) | 3-4 weeks |
| M5: Polish | Tier 4 (#16-20) | 2-3 weeks |

**Total estimate:** 15-20 weeks

---

## 5. StubConfig Changes

Current StubConfig is 32 bytes (23 bools + encAlgorithm + researchPackage + 7 pad).

New fields (requiring bit repacking or extension):

```c
struct StubConfig {
    // Existing (23 bools)
    bool bPatchAmsi;          // → RENAMED to bPatchlessAmsiEtw
    bool bPatchEtw;           // → MERGED into bPatchlessAmsiEtw
    bool bUnhookNtdll;        // → RENAMED to bUnhookKnownDlls
    bool bSyscall;            // → RENAMED to bIndirectSyscalls
    bool bKeyValidation;
    bool bMeltFile;
    bool bPersistence;
    bool bAntiDebug;
    bool bAntiVM;
    bool bAntiEmulator;
    bool bGuardPage;
    bool bRunPE;
    bool bModuleStomp;
    bool bCallbackProxy;
    bool bThreadPool;
    bool bPhantomDll;
    bool bSleepObf;
    bool bStageLoad;
    bool bStripMotw;
    bool bTlsCallback;
    // 3 more existing bools

    // New
    bool bFullDynamicAPI;      // #2
    bool bSpoofCallStack;      // #5
    bool bAntiMemScan;         // #6
    bool bRemoteInjection;     // #7
    bool bEkkoSleep;           // #8
    bool bDotNetLoading;       // #9
    bool bThreadNormalization; // #10
    bool bSideloadFormat;      // #11
    bool bBuildRandomization;  // #12
    bool bAntiDump;            // #13
    bool bStagedDelivery;      // #14
    bool bPerEdrProfile;       // #15

    BYTE encAlgorithm;         // existing
    BYTE researchPackage;      // existing
};
```

**Strategy:** Merge merged flags (bPatchAmsi+bPatchEtw → bPatchlessAmsiEtw), add new flags in freed slots, extend pad if needed. StubConfig size grows from 32 to 40 bytes.

**Version field:** First byte of StubConfig is `version` (currently 0x01). Builder validates version before patching.

```c
struct StubConfig {
    BYTE version;            // 0x02 for Tier 1+ (was 0x01 for original)
    // ... all flags and fields ...
};
```

**Migration Path (Builder → Stub Compatibility):**

```
StubPatcher.cs Logic:
  1. Read XCONFIG marker from stub binary
  2. Read first byte = version
  3. If version == 0x01 (original stub):
     - Use old 32-byte StubConfig layout
     - Only patch fields that exist in old layout
     - Warn: "Stub is legacy version, some features unavailable"
  4. If version == 0x02 (Tier 1+ stub):
     - Use new 40-byte StubConfig layout
     - Patch all fields including new ones
  5. If version > builder_max_version:
     - Error: "Stub version newer than builder. Update builder."
  6. FindMarker() adjusted: search for XCONFIG, read version byte first,
     then interpret rest according to version

Stub Entry.cpp Logic:
  1. Read StubConfig from XCONFIG marker
  2. Check version field
  3. If version < current: only use fields that exist in that version
  4. If version == current: use all fields
  5. Unknown flags default to false (safe default = technique disabled)
```

**XCONFIG Marker Size:**
- Version 0x01: marker contains exactly 32 bytes of config
- Version 0x02: marker contains exactly 40 bytes of config
- StubPatcher reads version first, then reads appropriate number of bytes
- FindMarker() does NOT assume fixed config size

---

## 6. Sentinel Marker Extensions

| Marker | Current | New |
|---|---|---|
| XCONFIG | 32 bytes StubConfig | 40 bytes (extended) |
| XKEYBLK | 32 bytes key | 32 bytes (unchanged) |
| XPAYLOD | inline payload (max 512KB) | inline payload (max 512KB) OR staged URL |
| XRESRC | cipher params | cipher params + API hash table + gadget offsets + EDR profile data |
| **XSPOOF** | — | Stack spoof frame descriptors (new) |
| **XGADGT** | — | Gadget pool entries (new) |
| **XSTAGE** | — | Staged delivery config: URL, DNS server, encryption key (new) |

---

## 7. Builder Changes Summary

| Builder Component | Change Type | Details |
|---|---|---|
| StubPatcher.cs | Extend | New markers (XSPOOF, XGADGT, XSTAGE), extended StubConfig |
| CryptoEngine.cs | No change | Existing ciphers sufficient |
| PEMutator.cs | Extend | Randomized pipeline order (#12) |
| BypassEngine.cs | Major extend | Per-EDR technique selection (#15), API hash generation (#2) |
| AvDatabase.cs | Extend | Active profiles instead of display-only |
| CodeSigner.cs | Extend | Certificate cloning (#16) |
| ConfigValidator.cs | Extend | New flags, dependency validation |
| New: ApiHashDB.cs | New | Generate CRC32C/djb2 hashes for all stub API needs |
| New: GadgetFinder.cs | New | Scan stub binary for 0F 05 C3 gadgets, generate pool |
| New: StagedConfig.cs | New | Staged delivery URL/encryption config generation |
| New: StackSpoofGen.cs | New | Generate synthetic frame descriptors for builder |
| WPF Views | Extend | New UI controls for Tier 1-4 features |

---

## 8. Acceptance Criteria

### Per-Module Acceptance

Each module must pass:
1. **Functional test:** Feature works in isolation against Defender
2. **Integration test:** Feature works alongside other Tier 1 modules
3. **Regression test:** Existing functionality (8 cipher engines, 18-layer metamorphism, etc.) unbroken
4. **Detection test:** VirusTotal scan ≤ 5/72 for standard payload with all Tier 1 features enabled

### Per-Tier Acceptance

- Tier 1: All 6 modules functional, stub compiles and executes, detection ≤ 5/72
- Tier 2: All 4 modules functional, staged delivery works, detection ≤ 3/72
- Tier 3: All 5 modules functional, sideload formats work, EDR profiles active
- Tier 4: All 5 modules functional, builder UX complete, automated testing pipeline

---

## 9. Risk Register

| Risk | Impact | Mitigation |
|---|---|---|
| Indirect syscalls SSN extraction fails on new Windows builds | High | Pattern + Halo's Gate + syscall table sorting fallback |
| VEH handler conflicts with existing GuardPage VEH | Medium | Single unified VEH handler, dispatch by exception code — requires POC before M2 |
| Call stack spoofing RSP pivot crashes on edge cases | High | Phased: v1=simple frame spoof (safe), v2=RSP pivot only after POC passes |
| KnownDlls object namespace varies across Windows versions | Low | Fallback to disk-based unhooking (existing code) |
| Staged delivery URL blocked by network proxy | Medium | DoH-resolved HTTPS + domain fronting fallback |
| StubConfig size change breaks builder-stub compatibility | High | Version field + migration path (see §5) |
| AMSI hooks active before WinMain (TLS callback phase) | High | Mini-unhook in TLS callback: resolve NtOpenSection inline, unhook before anti-check |
| Gadget pool empty on some Windows builds | Medium | Multi-tier fallback: indirect → hotpatch trampoline → direct syscall |
| .NET Assembly.Load from memory requires disk path | High | Custom AssemblyResolve handler + NtCreateSection memory staging |
| Certificate cloning ineffective against modern EDR | Medium | Research item: test against Defender signature validation before committing effort |
| Unified VEH handler race conditions (3 subscribers) | High | POC required: test GuardPage + PatchlessBypass + scanner-detect coexistence under load |

---

## 10. High-Risk POC Requirements

Следующие модули требуют Proof-of-Concept ДО полноценной реализации. POC — минимальный тестовый проект, подтверждающий, что техника работает в нашей конфигурации.

| POC | Что проверить | Критерий успеха | Когда |
|---|---|---|---|
| Unified VEH | GuardPage + PatchlessBypass + scanner detect в одном хендлере | Нет конфликтов, все три обработчика корректно диспетчатся | Перед M2 |
| RSP Pivot Stack Spoof | Spoofed call с RSP pivot на простом NtAllocateVirtualMemory | Стек-трейс показывает легитимные адреса, нет краша | Перед M2 Phase 2 |
| .NET Memory Load | Загрузка .NET assembly из памяти без диска через AssemblyResolve | Assembly выполняется, CLR AMSI обход работает | Перед M3 |
| Indirect Syscall Fallback | Gadget pool пуст → hotpatch trampoline → direct syscall fallback | Каждая стадия работает, stub не крашится при отсутствии гаджетов | Перед M1 Week 3 |
| TLS Callback Mini-Unhook | Unhooking внутри TLS callback до WinMain | AMSI хуки сняты до первого AmsiScanBuffer вызова | Перед M1 Week 1 |

---

## Related Specs

- [Tier 1: Core Evasion](tier1-core-evasion.md)
- [Tier 2: Advanced Evasion](tier2-advanced-evasion.md)
- [Tier 3: Competitive Edge](tier3-competitive-edge.md)
- [Tier 4: Polish](tier4-polish.md)
- [Roadmap](../roadmap.md)
