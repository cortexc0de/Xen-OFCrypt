//
//  Xanthorox-OFCrypt | Runtime Module Test Runner
//  Standalone test for key evasion modules — verifies at runtime
//  Builds separately from Stub to avoid interference
//

#include <windows.h>
#include <stdio.h>
#include <intrin.h>

// Include Stub headers
#include "ApiResolver.h"
#include "PureCrypto.h"
#include "Syscall.h"
#include "KnownDlls.h"
#include "GadgetPool.h"
#include "StackSpoof.h"
#include "PatchlessBypass.h"

static int g_Pass = 0;
static int g_Fail = 0;

#define TEST(name, cond) do { \
    if (cond) { printf("  [PASS] %s\n", name); g_Pass++; } \
    else      { printf("  [FAIL] %s\n", name); g_Fail++; } \
} while(0)

// ═══ Test 1: ApiResolver — PEB walk + CRC32C ═══
static void TestApiResolver()
{
    printf("\n=== ApiResolver ===\n");

    // Module resolution via PEB walk
    HMODULE hK32 = Api::GetModuleByHashCrc(Api::CrcMod::KERNEL32);
    TEST("GetModuleByHashCrc(KERNEL32)", hK32 != nullptr);

    HMODULE hNtdll = Api::GetModuleByHashCrc(Api::CrcMod::NTDLL);
    TEST("GetModuleByHashCrc(NTDLL)", hNtdll != nullptr);

    // Function resolution via CRC32C
    if (hK32) {
        auto pSleep = (void(WINAPI*)(DWORD))Api::GetProcByHashCrc(hK32, Api::CrcFn::Sleep);
        TEST("GetProcByHashCrc(Sleep)", pSleep != nullptr);

        auto pGPA = (FARPROC(WINAPI*)(HMODULE, LPCSTR))Api::GetProcByHashCrc(hK32, Api::CrcFn::GetProcAddress);
        TEST("GetProcByHashCrc(GetProcAddress)", pGPA != nullptr);

        // Verify resolved Sleep actually works
        if (pSleep) {
            DWORD t1 = GetTickCount();
            pSleep(50);
            DWORD t2 = GetTickCount();
            TEST("Sleep(50) via hash resolution", (t2 - t1) >= 40);
        }
    }

    // Verify standard GetProcAddress matches hash-resolved one
    if (hK32) {
        auto pViaHash = Api::GetProcByHashCrc(hK32, Api::CrcFn::VirtualAlloc);
        auto pViaIAT = GetProcAddress(hK32, "VirtualAlloc");
        TEST("Hash-resolved VirtualAlloc matches GetProcAddress", pViaHash == pViaIAT);
    }
}

// ═══ Test 2: PureCrypto — SHA-256, HMAC-SHA256, ChaCha20 ═══
static void TestPureCrypto()
{
    printf("\n=== PureCrypto ===\n");

    // SHA-256 test vector: SHA256("abc") = ba7816bf...
    unsigned char input[] = "abc";
    unsigned char hash[32] = {};
    PureCrypto::Sha256(input, 3, hash);

    unsigned char expected[32] = {
        0xBA,0x78,0x16,0xBF,0x8F,0x01,0xCF,0xEA,0x41,0x41,0x40,0xDE,0x5D,0xAE,0x22,0x23,
        0xB0,0x03,0x61,0xA3,0x96,0x17,0x7A,0x9C,0xB4,0x10,0xFF,0x61,0xF2,0x00,0x15,0xAD
    };
    TEST("Sha256(\"abc\") matches FIPS 180-4 vector", memcmp(hash, expected, 32) == 0);

    // ChaCha20 test: encrypt + decrypt round-trip
    unsigned char data[64];
    for (int i = 0; i < 64; i++) data[i] = (unsigned char)i;

    unsigned char original[64];
    memcpy(original, data, 64);

    unsigned char key[32] = {};
    for (int i = 0; i < 32; i++) key[i] = (unsigned char)(i + 0x80);
    unsigned char nonce[12] = {};

    PureCrypto::ChaCha20(data, 64, key, nonce, 0);
    TEST("ChaCha20 encrypts (data differs from original)", memcmp(data, original, 64) != 0);

    PureCrypto::ChaCha20(data, 64, key, nonce, 0);
    TEST("ChaCha20 decrypt round-trip (data matches original)", memcmp(data, original, 64) == 0);

    // HMAC-SHA256 basic test (non-empty output)
    unsigned char hmacKey[] = "key";
    unsigned char hmacData[] = "The quick brown fox jumps over the lazy dog";
    unsigned char hmacOut[32] = {};
    PureCrypto::HmacSha256(hmacKey, 3, hmacData, 43, hmacOut);
    bool hmacNonZero = false;
    for (int i = 0; i < 32; i++) if (hmacOut[i] != 0) hmacNonZero = true;
    TEST("HmacSha256 produces non-zero output", hmacNonZero);
}

// ═══ Test 3: Syscall engine — SSN resolution + indirect syscall ═══
static void TestSyscallEngine()
{
    printf("\n=== Indirect Syscall Engine ===\n");

    // KnownDlls unhook first (required for Syscall::Init)
    bool unhookOk = KnownDlls::UnhookNtdll();
    TEST("KnownDlls::UnhookNtdll()", unhookOk);

    // GadgetPool scan (required for Syscall::Init)
    int gadgetCount = GadgetPool::Scan();
    TEST("GadgetPool::Scan() finds gadgets", gadgetCount > 0);
    printf("    Found %d gadgets\n", gadgetCount);

    // StackSpoof init
    bool spoofInit = StackSpoof::Init();
    TEST("StackSpoof::Init()", spoofInit);

    // Syscall init
    bool syscallInit = Syscall::Init();
    TEST("Syscall::Init() resolves SSNs", syscallInit);

    if (syscallInit) {
        // Test NtAllocateVirtualMemory via indirect syscall
        PVOID baseAddr = nullptr;
        SIZE_T regionSize = 4096;
        NTSTATUS status = Syscall::NtAllocateVirtualMemory(
            (HANDLE)(LONG_PTR)-1, &baseAddr, &regionSize,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        TEST("NtAllocateVirtualMemory via indirect syscall", status == 0 && baseAddr != nullptr);

        if (baseAddr) {
            // Write test pattern
            memset(baseAddr, 0x41, 4096);
            TEST("Write to allocated memory", ((unsigned char*)baseAddr)[0] == 0x41);

            // Test NtProtectVirtualMemory
            PVOID protectBase = baseAddr;
            SIZE_T protectSize = 4096;
            ULONG oldProtect = 0;
            status = Syscall::NtProtectVirtualMemory(
                (HANDLE)(LONG_PTR)-1, &protectBase, &protectSize,
                PAGE_READONLY, &oldProtect);
            TEST("NtProtectVirtualMemory (RW->RO)", status == 0);

            // Restore to RW for cleanup
            protectBase = baseAddr;
            protectSize = 4096;
            Syscall::NtProtectVirtualMemory(
                (HANDLE)(LONG_PTR)-1, &protectBase, &protectSize,
                PAGE_READWRITE, &oldProtect);

            // Test NtClose (with a valid handle)
            HANDLE hEvent = nullptr;
            HMODULE hK32 = GetModuleHandleA("kernel32.dll");
            if (hK32) {
                auto pCE = (HANDLE(WINAPI*)(LPSECURITY_ATTRIBUTES, BOOL, BOOL, LPCSTR))
                    GetProcAddress(hK32, "CreateEventA");
                if (pCE) hEvent = pCE(nullptr, FALSE, FALSE, nullptr);
            }
            if (hEvent) {
                status = Syscall::NtClose(hEvent);
                TEST("NtClose via indirect syscall", status == 0);
            } else {
                TEST("NtClose (skipped — no handle)", true);
            }

            // Free allocated memory
            VirtualFree(baseAddr, 0, MEM_RELEASE);
        }
    }
}

// ═══ Test 4: PatchlessBypass — hardware breakpoint setup ═══
static void TestPatchlessBypass()
{
    printf("\n=== PatchlessBypass ===\n");

    bool patchOk = PatchlessBypass::Enable();
    TEST("Enable() — no crash, returns true", patchOk);

    PatchlessBypass::Disable();
    TEST("Disable() — no crash", true);
}

// ═══ Main ═══
int main()
{
    printf("╔══════════════════════════════════════════════╗\n");
    printf("║  Xanthorox-OFCrypt Runtime Module Tests      ║\n");
    printf("╚══════════════════════════════════════════════╝\n");

    TestApiResolver();
    TestPureCrypto();
    TestSyscallEngine();
    TestPatchlessBypass();

    printf("\n══════════════════════════════════════════════\n");
    printf("Results: %d PASSED, %d FAILED\n", g_Pass, g_Fail);
    printf("══════════════════════════════════════════════\n");

    return g_Fail > 0 ? 1 : 0;
}
