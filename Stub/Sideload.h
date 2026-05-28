#pragma once

// Sideload Delivery Format entry points
// CPL (control.exe), XLL (excel.exe), MSI (msiexec.exe)

// Shared payload execution chain — called by WinMain and all DLL exports
int PayloadMain(void* hInstance);

// DLL entry point (minimal — just saves hInstance)
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved);

// CPL: Control Panel Applet — called by control.exe
LONG CALLBACK CPlApplet(HWND hwndCPl, UINT msg, LPARAM lParam1, LPARAM lParam2);

// XLL: Excel Add-in — called by excel.exe on load
int __stdcall xlAutoOpen(void);

// MSI: Custom Action DLL — called by msiexec.exe
// MSIHANDLE is an unsigned int (from msi.h)
UINT __stdcall CustomActionEntry(unsigned int hInstall);
