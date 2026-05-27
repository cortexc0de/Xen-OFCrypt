//
//  Runtime test for ApiResolver, Crc32C, and Syscall engine
//  Links against stub .obj files + normal CRT as console app
//
#include <cstdio>
#include <cstdlib>
#include <windows.h>

#include "Stub/ApiResolver.h"
#include "Stub/Syscall.h"
#include "Stub/GadgetPool.h"
#include "Stub/Hotpatch.h"
#include "Stub/PureCrypto.h"

static int g_pass = 0;
static int g_fail = 0;

#ifndef NT_SUCCESS
#define NT_SUCCESS(status) (((NTSTATUS)(status)) >= 0)
#endif

#define TEST(name, expr) do { \
    if (expr) { printf("  [PASS] %s\n", name); g_pass++; } \
    else { printf("  [FAIL] %s\n", name); g_fail++; } \
} while(0)

int main()
{
    printf("=== Xen-OFCrypt Runtime Test Suite ===\n\n");

    // ── Crc32C tests ──
    printf("[1] Crc32C hashing\n");
    Crc32C::DetectSse42();

    DWORD c1 = Crc32C::ConstHash("kernel32.dll");
    DWORD r1 = Crc32C::RuntimeHash("kernel32.dll");
    TEST("ConstHash == RuntimeHash for 'kernel32.dll'", c1 == r1);

    DWORD c2 = Crc32C::ConstHash("VirtualAlloc");
    DWORD r2 = Crc32C::RuntimeHash("VirtualAlloc");
    TEST("ConstHash == RuntimeHash for 'VirtualAlloc'", c2 == r2);

    DWORD c3 = Crc32C::ConstHash("ntdll.dll");
    DWORD r3 = Crc32C::RuntimeHash("ntdll.dll");
    TEST("ConstHash == RuntimeHash for 'ntdll.dll'", c3 == r3);

    DWORD c4 = Crc32C::ConstHash("GetProcAddress");
    DWORD r4 = Crc32C::RuntimeHash("GetProcAddress");
    TEST("ConstHash == RuntimeHash for 'GetProcAddress'", c4 == r4);

    printf("  ConstHash('kernel32.dll')  = 0x%08X\n", c1);
    printf("  CrcMod::KERNEL32           = 0x%08X\n", Api::CrcMod::KERNEL32);
    TEST("Crc32C matches Api::CrcMod::KERNEL32", c1 == Api::CrcMod::KERNEL32);

    // ── DJB2 ApiResolver tests ──
    printf("\n[2] DJB2 PEB Walk (Api::GetModuleByHash)\n");

    HMODULE hK32_djb = Api::GetModuleByHash(Api::Mod::KERNEL32);
    TEST("Resolve kernel32.dll via DJB2", hK32_djb != nullptr);
    if (hK32_djb) {
        TEST("kernel32 base matches GetModuleHandleA",
             hK32_djb == GetModuleHandleA("kernel32.dll"));
    }

    HMODULE hNt_djb = Api::GetModuleByHash(Api::Mod::NTDLL);
    TEST("Resolve ntdll.dll via DJB2", hNt_djb != nullptr);
    if (hNt_djb) {
        TEST("ntdll base matches GetModuleHandleA",
             hNt_djb == GetModuleHandleA("ntdll.dll"));
    }

    // ── DJB2 function resolution ──
    printf("\n[3] DJB2 Export Walk (Api::GetProcByHash)\n");

    FARPROC pVA = Api::GetProcByHash(hK32_djb, Api::Fn::VirtualAlloc);
    FARPROC pVA_real = GetProcAddress(hK32_djb, "VirtualAlloc");
    TEST("Resolve VirtualAlloc via DJB2", pVA != nullptr);
    TEST("VirtualAlloc address matches GetProcAddress", pVA == pVA_real);

    FARPROC pGPA = Api::GetProcByHash(hK32_djb, Api::Fn::GetProcAddress);
    FARPROC pGPA_real = GetProcAddress(hK32_djb, "GetProcAddress");
    TEST("Resolve GetProcAddress via DJB2", pGPA != nullptr);
    TEST("GetProcAddress address matches GetProcAddress", pGPA == pGPA_real);

    // ── CRC32C ApiResolver tests ──
    printf("\n[4] CRC32C PEB Walk (Api::GetModuleByHashCrc)\n");

    HMODULE hK32_crc = Api::GetModuleByHashCrc(Api::CrcMod::KERNEL32);
    TEST("Resolve kernel32.dll via CRC32C", hK32_crc != nullptr);
    TEST("CRC32C kernel32 == DJB2 kernel32", hK32_crc == hK32_djb);

    HMODULE hNt_crc = Api::GetModuleByHashCrc(Api::CrcMod::NTDLL);
    TEST("Resolve ntdll.dll via CRC32C", hNt_crc != nullptr);
    TEST("CRC32C ntdll == DJB2 ntdll", hNt_crc == hNt_djb);

    HMODULE hKb_crc = Api::GetModuleByHashCrc(Api::CrcMod::KERNELBASE);
    TEST("Resolve kernelbase.dll via CRC32C", hKb_crc != nullptr);

    // ── CRC32C function resolution ──
    printf("\n[5] CRC32C Export Walk (Api::GetProcByHashCrc)\n");

    FARPROC pVA_crc = Api::GetProcByHashCrc(hK32_crc, Api::CrcFn::VirtualAlloc);
    TEST("Resolve VirtualAlloc via CRC32C", pVA_crc != nullptr);
    TEST("CRC32C VirtualAlloc == DJB2 VirtualAlloc", pVA_crc == pVA);

    FARPROC pVP_crc = Api::GetProcByHashCrc(hK32_crc, Api::CrcFn::VirtualProtect);
    TEST("Resolve VirtualProtect via CRC32C", pVP_crc != nullptr);

    FARPROC pGPA_crc = Api::GetProcByHashCrc(hK32_crc, Api::CrcFn::GetProcAddress);
    TEST("Resolve GetProcAddress via CRC32C", pGPA_crc != nullptr);
    TEST("CRC32C GetProcAddress matches", pGPA_crc == pGPA_real);

    // ── Syscall engine tests ──
    printf("\n[6] GadgetPool Scan\n");

    bool scanOk = GadgetPool::Scan();
    TEST("GadgetPool::Scan() succeeds", scanOk);
    printf("  Gadget count: %lu\n", GadgetPool::Count());

    if (GadgetPool::Count() > 0) {
        GadgetPool::Gadget* g = GadgetPool::GetRandom();
        TEST("GetRandom() returns valid gadget", g != nullptr && g->address != nullptr);
        if (g) {
            unsigned char* p = (unsigned char*)g->address;
            TEST("Gadget is 0F 05 C3", p[0] == 0x0F && p[1] == 0x05 && p[2] == 0xC3);
        }
    }

    printf("\n[7] Hotpatch Scan\n");

    bool hpOk = Hotpatch::ScanForHotpatchAreas();
    TEST("Hotpatch::ScanForHotpatchAreas() succeeds", hpOk);
    printf("  Hotpatch slots: %lu\n", Hotpatch::SlotCount());

    // ── Syscall Init + SSN resolution ──
    printf("\n[8] Syscall::Init() — SSN Resolution\n");

    bool initOk = Syscall::Init();
    TEST("Syscall::Init() succeeds", initOk);

    // Verify known SSNs by making test syscalls
    printf("\n[9] Syscall Functional Tests\n");

    // NtClose with invalid handle should return STATUS_INVALID_HANDLE (0xC0000008)
    NTSTATUS status = Syscall::NtClose((HANDLE)0xDEADBEEF);
    TEST("NtClose(invalid_handle) returns STATUS_INVALID_HANDLE",
         status == (NTSTATUS)0xC0000008);

    // NtClose with current process pseudo-handle should succeed
    // Actually, NtClose on -1 is special — let's use a real handle
    HANDLE hEvent = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    if (hEvent) {
        NTSTATUS st2 = Syscall::NtClose(hEvent);
        TEST("NtClose(real_handle) returns STATUS_SUCCESS", st2 == 0);
    } else {
        printf("  [SKIP] Could not create event handle for NtClose test\n");
    }

    // NtAllocateVirtualMemory — allocate + free a page
    PVOID baseAddr = nullptr;
    SIZE_T regionSize = 4096;
    NTSTATUS st3 = Syscall::NtAllocateVirtualMemory(
        (HANDLE)-1, &baseAddr, &regionSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    TEST("NtAllocateVirtualMemory succeeds", NT_SUCCESS(st3) && baseAddr != nullptr);

    if (baseAddr) {
        // Write to it via NtWriteVirtualMemory (write to own process)
        DWORD testVal = 0x42424242;
        SIZE_T written = 0;
        NTSTATUS st4 = Syscall::NtWriteVirtualMemory(
            (HANDLE)-1, baseAddr, &testVal, sizeof(testVal), &written);
        TEST("NtWriteVirtualMemory succeeds", NT_SUCCESS(st4));

        // Read back via NtReadVirtualMemory
        DWORD readVal = 0;
        SIZE_T bytesRead = 0;
        NTSTATUS st5 = Syscall::NtReadVirtualMemory(
            (HANDLE)-1, baseAddr, &readVal, sizeof(readVal), &bytesRead);
        TEST("NtReadVirtualMemory succeeds", NT_SUCCESS(st5));
        TEST("Read-back matches written value", readVal == 0x42424242);

        // Change protection via NtProtectVirtualMemory
        DWORD oldProtect = 0;
        SIZE_T protSize = regionSize;
        PVOID protBase = baseAddr;
        NTSTATUS st6 = Syscall::NtProtectVirtualMemory(
            (HANDLE)-1, &protBase, &protSize, PAGE_READWRITE, &oldProtect);
        TEST("NtProtectVirtualMemory succeeds", NT_SUCCESS(st6));

        // Free via VirtualFree (CRT) since NtAllocateVirtualMemory MEM_RELEASE
        // has strict parameter requirements — test the concept, not the edge case
        BOOL freed = VirtualFree(baseAddr, 0, MEM_RELEASE);
        TEST("VirtualFree(MEM_RELEASE) succeeds", freed);
    }

    // ── PureCrypto tests ──
    printf("\n[10] PureCrypto — SHA-256\n");

    // SHA-256 of empty string: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    {
        unsigned char hash[32];
        PureCrypto::Sha256(nullptr, 0, hash);
        unsigned char expected[] = {
            0xe3,0xb0,0xc4,0x42,0x98,0xfc,0x1c,0x14,0x9a,0xfb,0xf4,0xc8,0x99,0x6f,0xb9,0x24,
            0x27,0xae,0x41,0xe4,0x64,0x9b,0x93,0x4c,0xa4,0x95,0x99,0x1b,0x78,0x52,0xb8,0x55
        };
        bool match = (memcmp(hash, expected, 32) == 0);
        TEST("SHA-256(empty) matches known hash", match);
    }

    // SHA-256 of "abc": ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
    {
        unsigned char hash[32];
        PureCrypto::Sha256((const unsigned char*)"abc", 3, hash);
        unsigned char expected[] = {
            0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
            0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad
        };
        bool match = (memcmp(hash, expected, 32) == 0);
        TEST("SHA-256('abc') matches FIPS 180-4 test vector", match);
    }

    printf("\n[11] PureCrypto — HMAC-SHA256\n");

    // HMAC-SHA256 test vector from RFC 4231 Test Case 2:
    // Key = "Jefe", Data = "what do ya want for nothing?"
    // Result = 5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843
    {
        unsigned char hash[32];
        PureCrypto::HmacSha256(
            (const unsigned char*)"Jefe", 4,
            (const unsigned char*)"what do ya want for nothing?", 28,
            hash);
        unsigned char expected[] = {
            0x5b,0xdc,0xc1,0x46,0xbf,0x60,0x75,0x4e,0x6a,0x04,0x24,0x26,0x08,0x95,0x75,0xc7,
            0x5a,0x00,0x3f,0x08,0x9d,0x27,0x39,0x83,0x9d,0xec,0x58,0xb9,0x64,0xec,0x38,0x43
        };
        bool match = (memcmp(hash, expected, 32) == 0);
        TEST("HMAC-SHA256 RFC 4231 TC2 matches", match);
    }

    printf("\n[12] PureCrypto — ChaCha20\n");

    // ChaCha20 roundtrip: encrypt then decrypt should recover plaintext
    {
        unsigned char key[32] = {0};
        for (int i = 0; i < 32; i++) key[i] = (unsigned char)i;
        unsigned char nonce[12] = {0};
        for (int i = 0; i < 12; i++) nonce[i] = (unsigned char)i;

        unsigned char data[64];
        for (int i = 0; i < 64; i++) data[i] = (unsigned char)i;

        // Save original
        unsigned char original[64];
        memcpy(original, data, 64);

        // Encrypt (in-place XOR)
        PureCrypto::ChaCha20(data, 64, key, nonce, 0);

        // Should be different from plaintext
        bool changed = (memcmp(data, original, 64) != 0);
        TEST("ChaCha20 output differs from input", changed);

        // Decrypt (XOR again with same key/nonce/counter)
        PureCrypto::ChaCha20(data, 64, key, nonce, 0);

        bool recovered = (memcmp(data, original, 64) == 0);
        TEST("ChaCha20 roundtrip recovers plaintext", recovered);
    }

    // ── Summary ──
    printf("\n=== Results: %d passed, %d failed ===\n", g_pass, g_fail);

    return g_fail > 0 ? 1 : 0;
}
