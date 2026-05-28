# Tier 3: Competitive Edge — Detailed Specification

**Parent:** [Master Design](2026-05-25-xen-premium-master-design.md)
**Status:** Approved
**Priority:** COMPETITIVE EDGE
**Milestone:** M4
**Dependencies:** Tier 1 + Tier 2 (Ekko sleep, indirect syscalls, stack spoofing)

---

## 11. Sideload Delivery Formats

**Files to add:** Per-format loader modules
**StubConfig flag:** `bSideloadFormat` + `sideloadFormatType` field

### Architecture

Current: Only EXE output. Payload runs as standalone executable.
New: Multiple Application Whitelisting bypass formats — each is a different delivery vector.

### Supported Formats

#### 11.1 CPL (Control Panel Applet)

```
Format: DLL exporting CPlApplet function
Mechanism:
  1. DLL with CPlApplet(HWND, UINT, LPARAM, LPARAM) export
  2. When double-clicked or executed via control.exe:
     - WM_INIT = CPL_INIT → init
     - CPL_GETCOUNT → returns 1
     - CPL_INQUIRE → fill NEWCPLINFO struct
     - CPL_DBLCLK → trigger payload execution
  3. control.exe runs the CPL → legitimate parent process
  4. Application Whitelisting allows .cpl files

Builder output: payload.cpl (renamed DLL with CPlApplet export)
```

#### 11.2 XLL (Excel Add-In)

```
Format: DLL exporting xlAutoOpen function
Mechanism:
  1. DLL with xlAutoOpen() export
  2. When loaded by Excel.exe (via File → Open or sideload):
     - Excel calls xlAutoOpen() automatically
     - xlAutoOpen → decrypt + execute payload
  3. Excel.exe is a trusted application (AppLocker whitelist)
  4. XLL loading is normal business behavior

Builder output: addin.xll (renamed DLL with xlAutoOpen export)
```

#### 11.3 MSI (Windows Installer Package)

```
Format: MSI with custom action DLL
Mechanism:
  1. Build MSI with embedded custom action DLL
  2. Custom action DLL contains stub code
  3. When MSI is installed (msiexec.exe):
     - msiexec.exe loads custom action DLL
     - DLL_PROCESS_ATTACH → decrypt + execute payload
  4. msiexec.exe is a trusted system process
  5. MSI installation is normal enterprise behavior

Builder output: update.msi (MSI package with embedded stub DLL)
```

#### 11.4 HTA (HTML Application)

```
Format: HTML file with <HTA:APPLICATION> tag + embedded script
Mechanism:
  1. HTA file with embedded VBScript/JScript
  2. Script writes stub binary to disk and executes via WScript.Shell
  3. mshta.exe processes the HTA → legitimate parent process
  4. mshta.exe bypasses many Application Whitelisting rules

Builder output: page.hta (HTML with embedded stub + loader script)
```

#### 11.5 JScript/VBS (Windows Script)

```
Format: .js or .vbs file with stub loader
Mechanism:
  1. Script file creates stub binary via ADODB.Stream + SaveToFile
  2. Executes via WScript.Shell.Run or Shell.Application
  3. wscript.exe/cscript.exe is the parent process
  4. Script execution is common in enterprise environments

Builder output: update.js or update.vbs
```

### Builder Integration

```
Builder UI: dropdown to select output format
  - EXE (default, existing)
  - CPL (Control Panel Applet)
  - XLL (Excel Add-In)
  - MSI (Installer Package)
  - HTA (HTML Application)
  - JS (JScript)
  - VBS (VBScript)

Each format generates:
  - Appropriate wrapper code (CPlApplet/xlAutoOpen/DllMain/etc.)
  - Correct PE structure (DLL vs EXE, proper exports)
  - File extension matching format
  - Staged delivery config embedded in wrapper
```

### Stub Architecture for Sideload

```
For DLL-based formats (CPL, XLL):
  - Stub compiled as DLL instead of EXE
  - Export function calls main stub logic
  - Same internal architecture (cipher engines, evasion, etc.)
  - StubConfig/payload in same .xthrx section

For script-based formats (HTA, JS, VBS):
  - Script is a thin loader
  - Downloads or extracts stub EXE/DLL
  - Executes stub via appropriate method
  - Staged delivery primary method for these formats
```

### Testing

- CPL: opens in control.exe, payload executes on double-click
- XLL: loads in Excel.exe, xlAutoOpen fires, payload executes
- MSI: installs via msiexec.exe, custom action DLL loads
- HTA: opens in mshta.exe, script downloads+executes stub
- JS/VBS: runs in wscript.exe, stub extracted and executed
- All formats pass Application Whitelisting (AppLocker default rules)

---

## 12. Build Randomization Engine

**Files to modify:** `PEMutator.cs`
**StubConfig flag:** `bBuildRandomization`

### Architecture

Current: 18-layer metamorphism pipeline runs in fixed order (PEMutator.cs).
Problem: Same order every build → detectable pattern across builds.

New: Randomized pipeline + variable parameters per build.

### Randomization Dimensions

```
1. Mutation Stage Order
   Current: fixed sequence [timestamp→Rich header→section names→...→checksum]
   New: random permutation of stages, respecting dependencies:
   - Checksum repair MUST be last (depends on all other changes)
   - Entropy equalization after section name/junk code changes
   - Certificate padding after certificate injection
   All other stages can be in any order.

2. Junk Layer Count
   Current: fixed number of junk code blocks
   New: random between MIN_JUNK_LAYERS and MAX_JUNK_LAYERS per build
   Range: 3-12 layers, randomly selected

3. Entry Point Randomization
   Current: entry point at fixed offset
   New: entry point redirected through junk code trampoline chain
   - Random number of JMP instructions before reaching real entry
   - Length: 1-5 JMP chain with random NOP padding

4. Section Name Pool
   Current: from fixed list of .text/.data/.rdata/etc.
   New: generate random 8-char section names that look legitimate
   - Mimic real compiler output patterns
   - Keep .xthrx section name fixed (builder-stub contract)

5. Resource Content Randomization
   Current: resource mimicry picks from fixed database
   New: pick random legitimate PE resources to embed
   - Random icon from icon pool
   - Random version info from template pool
   - Random manifest from manifest pool
```

### Per-Build Seed

```
Each build generates a random seed (64-bit).
Seed determines ALL randomization decisions for that build.
Same seed → same output (reproducible for debugging).
Different seed → completely different binary structure.

Seed stored in build log (not in stub).
```

### PEMutator Pipeline Dependency Rules

```
Hard dependencies (order must be preserved):
  junk_code → entropy_equalization (entropy changes after junk added)
  section_names → entropy_equalization (section rename changes entropy)
  certificate_injection → certificate_padding (pad after cert)
  ALL mutations → checksum_repair (checksum depends on final bytes)

Soft dependencies (recommended but not required):
  timestamp → rich_header (timestamp should match Rich header)
  metadata_cloning → version_info (consistent metadata)
  icon_injection → resource_mimicry (icon is a resource)

Randomizable stages (can be in any order):
  timestamp, rich_header, section_names, junk_code, IAT_camouflage,
  semantic_dead_code, exception_handlers, metadata_cloning,
  string_table, version_info, icon_injection, realistic_timestamp
```

### Testing

- 10 consecutive builds with different seeds → all produce different binaries
- Same seed produces identical binary (reproducibility)
- All randomized builds pass functional testing (payload executes correctly)
- VT detection varies across builds (not identical hash)

---

## 13. Anti-Dump Enhancement

**Files to modify:** `GuardPage.h`, `GuardPage.cpp`, `Entry.cpp`
**Files to add:** `AntiDump.h`, `AntiDump.cpp`
**StubConfig flag:** `bAntiDump`

### Architecture

Current: Guard Page + VEH auto re-encryption on memory scan read.
Problem: Process dumpers (procexp, taskmgr, custom tools) can still dump process memory.

New: Multi-layer anti-dumping.

### Anti-Dump Techniques

```
1. Erase PE Headers
   After stub is loaded and running:
   a. Locate our module base address (PEB → LDR_DATA_TABLE_ENTRY)
   b. Overwrite DOS header (e_magic → 0, e_lfanew → 0)
   c. Overwrite NT header signature ("PE\0\0" → 0)
   d. Result: dumpers cannot reconstruct PE from memory (no headers)
   e. We keep internal reference to base address for our own use

2. Section Re-Encryption on Access Detection
   Enhanced Guard Page behavior:
   a. Set PAGE_GUARD on all sections after we're done initializing
   b. When external process reads our memory:
      - STATUS_GUARD_PAGE_VIOLATION fires
      - VEH handler XOR-encrypts the page before allowing read
      - Dumper gets encrypted garbage
   c. Our own code access:
      - VEH handler detects internal access (return address in our module)
      - Decrypts page, sets PAGE_GUARD again, continues execution

3. ReadProcessMemory Hook Detection
   Monitor for ReadProcessMemory calls targeting our process:
   a. NtReadVirtualMemory is called from external process
   b. If target address is in our module's range:
      - Immediately encrypt the region
      - Let the read complete (returns garbage)
      - Decrypt after read completes
   Implementation: APC-based monitoring thread or ETW consumer

4. Anti-Debug Breakpoint Detection
   Enhanced over existing AntiCheck:
   a. Check DR0-DR3 for hardware breakpoints (not set by us)
   b. Check for software breakpoints (0xCC bytes in our code)
   c. Check NtQueryInformationProcess(ProcessDebugPort)
   d. If detected: erase PE headers immediately, zero memory
```

### Integration with Existing Guard Page

```
Current GuardPage VEH handles STATUS_GUARD_PAGE_VIOLATION.
Enhanced: add external vs internal access discrimination.

External access pattern:
  - Faulting address in our module range
  - Return address NOT in our module range
  → Encrypt before read, decrypt after

Internal access pattern:
  - Faulting address in our module range
  - Return address IN our module range
  → Decrypt, execute, re-set PAGE_GUARD on next page boundary
```

### Testing

- Procexp dump: produces corrupted/encrypted dump
- Taskmgr dump: produces corrupted dump
- procdump.exe: produces garbage output
- Custom ReadProcessMemory scanner: gets encrypted data
- Our code still functions correctly (internal access decrypted by VEH)

---

## 14. Staged Payload Delivery

**Files to add:** `StagedDelivery.h`, `StagedDelivery.cpp`
**StubConfig flag:** `bStagedDelivery`
**New sentinel marker:** XSTAGE

### Architecture

Current: Payload embedded inline in XPAYLOD marker (max 512KB).
New: Stub downloads payload from remote server after environment validation.

### Delivery Protocol

```
Phase 1: Environment Validation (before download)
  1. Check anti-analysis (AntiCheck + AntiEmul)
  2. Check network connectivity
  3. Check EDR presence (AvDatabase + BypassEngine profiles)
  4. If environment fails validation → exit without downloading

Phase 2: Payload Download
  Method 1: HTTPS (primary, самый быстрый)
    - Standard HTTPS GET to staging URL
    - TLS 1.2+ required
    - Custom headers for identification (optional)
    - Поддержка chunked transfer для больших payloads
    - Скорость: ограничена только bandwidth

  Method 2: DoH-Resolved HTTPS (ПРОБЛЕМА #5 — исправлено)
    ПРОБЛЕМА: Предыдущая спека предлагала DNS TXT records для payload.
    TXT record = 255 байт максимум. Payload 5MB = ~20000 DNS запросов.
    Это часы, а не секунды. Неприемлемо.

    ИСПРАВЛЕНИЕ: DoH используется ТОЛЬКО для DNS resolution, не для transfer.
    1. Resolve staging domain через DoH (cloudflare-dns.com/1.1.1.1/dns-query)
       - Запрос A/AAAA record → получаем IP staging сервера
       - DoH скрывает DNS запрос от локального DNS мониторинга
    2. Устанавливаем HTTPS соединение НАПРЯМУЮ к полученному IP
       - SNI = staging domain (или CDN domain для fronting)
       - Обычный HTTPS GET/POST для payload transfer
       - Скорость как у обычного HTTPS
    3. Преимущество: DNS запрос скрыт через DoH, но transfer быстрый

  Method 3: Domain Fronting
    - HTTPS connection to CDN domain (e.g., cloudfront.net)
    - Host header = staging domain behind CDN
    - CDN routes to correct origin based on Host header
    - Network monitoring sees only CDN traffic
    - Note: многие CDN закрывают domain fronting (CloudFront ограничил)
    - Fallback: использовать менее популярные CDN (Fastly, Akamai)

Phase 3: Payload Decryption
  1. Downloaded payload is encrypted with separate key
  2. XSTAGE marker contains: URL/DoH server, encryption key, chunk size
  3. Decrypt using same cipher engine as inline payload
  4. Execute via same execution methods (RunPE, ModuleStomp, etc.)

Phase 4: Cleanup
  1. Erase downloaded payload from memory after decryption
  2. Erase XSTAGE marker data
  3. No traces of staging URL or encryption key
```

### XSTAGE Marker Format

```
Offset  Size    Field
0       4       TotalPayloadSize
4       4       ChunkSize (for chunked download, default 64KB)
8       1       DeliveryMethod (0=HTTPS, 1=DoH-Resolved HTTPS, 2=DomainFronting)
9       1       EncryptionAlgorithm (same enum as encAlgorithm)
10      32      EncryptionKey
42      256     StagingURL (null-terminated, max 255 chars + null)
298     256     DoHServer (null-terminated, e.g., "cloudflare-dns.com/1.1.1.1/dns-query")
554     256     FrontingCDN (null-terminated, e.g., "d1a2b3c4.cloudfront.net")
810     2       Reserved
812     ...     (padding to alignment)

Total XSTAGE size: ~812 bytes
```

### Builder Integration

```
Builder UI additions:
  - Radio: Inline / Staged delivery
  - If Staged:
    - URL input field
    - Delivery method dropdown (HTTPS/DoH/DomainFronting)
    - Encryption algorithm selection
    - Chunk size configuration
  - Builder generates XSTAGE marker and patches into stub
  - Builder does NOT embed payload in XPAYLOD (sets PayloadSize=0)
  - Payload uploaded separately to staging server
```

### Testing

- HTTPS download: stub downloads and decrypts payload from test server
- DoH download: stub resolves TXT records and assembles payload
- Domain fronting: stub connects through CDN with correct Host header
- Environment validation: stub exits in VM/sandbox without downloading
- No payload data in stub binary (only staging config)

---

## 15. Per-EDR Countermeasure Profiles

**Files to modify:** `BypassEngine.cs`, `AvDatabase.cs`, stub `Entry.cpp`
**StubConfig flag:** `bPerEdrProfile`

### Architecture

Current: AvDatabase.cs has 25+ AV/EDR profiles (display only in UI).
Current: BypassEngine.cs computes countermeasures but doesn't generate per-product config.

New: Active per-EDR technique selection — builder generates custom stub config per target EDR.

### EDR Detection Capabilities Database

```
Profile: Microsoft Defender for Endpoint
  Detection methods:
    - AMSI (AmsiScanBuffer)
    - ETW (EtwEventWrite + Microsoft-Antimalware-Scan-Interface provider)
    - Memory scanning (regular VirtualQuery walks)
    - Behavior monitoring (AMSI + process creation monitoring)
    - Network inspection (WFP filter for HTTP/HTTPS)
  Effective countermeasures:
    - Patchless AMSI bypass (critical)
    - ETW bypass (critical)
    - KnownDlls unhooking (high)
    - Indirect syscalls (high)
    - Call stack spoofing (medium)
    - Anti-memory scanning (high)
    - Sleep obfuscation (medium)
    - Thread normalization (medium)
  Less effective:
    - Call stack spoofing (Defender doesn't deep stack walk)
    - Certificate cloning (SmartScreen only, not Defender)

Profile: Universal Baseline
  Applies to all EDRs:
    - Patchless AMSI/ETW bypass
    - KnownDlls unhooking
    - Indirect syscalls
    - Full dynamic API resolution
    - Anti-memory scanning
  These are always-on regardless of target EDR
```

### BypassEngine Output

```
Current: BypassEngine computes display-only recommendations
New: BypassEngine generates technique configuration:

class BypassProfile {
    string TargetEdr;           // "Defender", "CrowdStrike", etc.
    bool EnableAmsiBypass;
    bool EnableEtwBypass;
    bool EnableUnhooking;
    bool EnableIndirectSyscalls;
    bool EnableStackSpoofing;
    bool EnableAntiMemScan;
    bool EnableSleepObf;
    bool EnableThreadNormalization;
    bool EnableRemoteInjection;
    // ... per-technique enable/disable
    Dictionary<string, string> TechniqueParams;  // Per-product tuning
}

// For Defender:
profile = new BypassProfile {
    TargetEdr = "Defender",
    EnableAmsiBypass = true,   // critical
    EnableEtwBypass = true,    // critical
    EnableUnhooking = true,    // high
    EnableIndirectSyscalls = true, // high
    EnableStackSpoofing = false,   // low value for Defender
    EnableAntiMemScan = true,  // high
    EnableSleepObf = true,     // medium
    EnableThreadNormalization = true, // medium
};

// BypassEngine writes this into StubConfig + XRESRC
// Stub reads profile and enables/disables techniques at runtime
```

### Stub-Side Profile Application

```
In Entry.cpp boot sequence:
  1. Read EDR profile from XRESRC
  2. If bPerEdrProfile is set:
     a. Check current system for known EDR products (AvDatabase signatures)
     b. Match detected EDR to profile
     c. Enable/disable techniques based on profile
     d. Skip techniques that are disabled for this EDR
  3. If no specific EDR detected:
     a. Use Universal Baseline (all Tier 1 techniques enabled)
     b. Enable all techniques as defensive measure
```

### EDR Detection in Stub

```
Stub-side EDR detection (lightweight, no disk signatures):
  1. Process enumeration: check for known EDR process names
     - MsMpEng.exe (Defender), CSFalconService.exe (CrowdStrike), etc.
  2. Module enumeration: check for loaded EDR DLLs
     - MpEngine.dll (Defender), CSFalconContainer.dll (CrowdStrike)
  3. Service enumeration: check for running EDR services
     - WinDefend (Defender), CSFalconService (CrowdStrike)
  4. Registry check: known EDR installation keys
     - HKLM\SOFTWARE\Microsoft\Windows Defender (Defender)
  5. All checks via ApiResolver (no IAT imports for these)

Detection results stored in stub memory, not persisted.
Used only for technique selection, not for reporting.
```

### Testing

- Defender profile: stub disables stack spoofing (low value), enables all others
- Universal profile: all Tier 1 techniques enabled
- EDR detection correctly identifies Defender on test system
- Profile application modifies boot sequence (techniques skipped if disabled)
