//
//  ClrHostDll — CLR Hosting DLL with CRT support
//
//  This DLL provides a CRT-initialized environment for CLR hosting.
//  The /NODEFAULTLIB stub loads this DLL via LoadLibraryW and calls
//  ExecuteClr() via GetProcAddress. This gives CLR the SEH infrastructure
//  it requires for managed/unmanaged code transitions.
//
//  Build: cl /O2 /MT /LD /EHsc ClrHostDll.cpp /link ole32.lib mscoree.lib /DEF:ClrHost.def
//

#include <windows.h>
#include <metahost.h>
#include <stdio.h>

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "mscoree.lib")

// Exported function: called by the stub to execute a .NET assembly
//   payloadPath  — full path to the .NET assembly on disk
//   className    — fully-qualified class name (e.g. L"E2EMarker")
//   methodName   — static method name (e.g. L"Run")
//   stringArg    — string argument to pass (or L"")
//   pRetVal      — receives the method's return value
// Returns: HRESULT from ExecuteInDefaultAppDomain
extern "C" __declspec(dllexport)
HRESULT WINAPI ExecuteClr(
    LPCWSTR payloadPath,
    LPCWSTR className,
    LPCWSTR methodName,
    LPCWSTR stringArg,
    DWORD*  pRetVal)
{
    if (!payloadPath || !className || !methodName || !pRetVal)
        return E_INVALIDARG;

    *pRetVal = 0xFFFF;

    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (hr != S_OK && hr != S_FALSE && hr != RPC_E_CHANGED_MODE) {
        // Try STA as fallback
        hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
        if (hr != S_OK && hr != S_FALSE && hr != RPC_E_CHANGED_MODE)
            return hr;
    }

    ICLRMetaHost* pMeta = nullptr;
    hr = CLRCreateInstance(CLSID_CLRMetaHost, IID_ICLRMetaHost, (void**)&pMeta);
    if (FAILED(hr)) { CoUninitialize(); return hr; }

    ICLRRuntimeInfo* pInfo = nullptr;
    hr = pMeta->GetRuntime(L"v4.0.30319", IID_ICLRRuntimeInfo, (void**)&pInfo);
    pMeta->Release();
    if (FAILED(hr)) { CoUninitialize(); return hr; }

    BOOL loadable = FALSE;
    pInfo->IsLoadable(&loadable);
    if (!loadable) { pInfo->Release(); CoUninitialize(); return E_FAIL; }

    ICLRRuntimeHost* pHost = nullptr;
    hr = pInfo->GetInterface(CLSID_CLRRuntimeHost, IID_ICLRRuntimeHost, (void**)&pHost);
    pInfo->Release();
    if (FAILED(hr)) { CoUninitialize(); return hr; }

    hr = pHost->Start();
    if (FAILED(hr)) { pHost->Release(); CoUninitialize(); return hr; }

    hr = pHost->ExecuteInDefaultAppDomain(
        payloadPath, className, methodName, stringArg, pRetVal);

    pHost->Stop();
    pHost->Release();
    CoUninitialize();
    return hr;
}

// Optional: write debug step to C:\temp\clr_step_N.txt
extern "C" __declspec(dllexport)
void WINAPI ClrHostDebug(int step, long val)
{
    char buf[64];
    int len = sprintf_s(buf, sizeof(buf), "%d v=%ld", step, val);
    char path[MAX_PATH];
    sprintf_s(path, sizeof(path), "C:\\temp\\clr_step_%d.txt", step);

    HANDLE h = CreateFileA(path, GENERIC_WRITE, 0, nullptr,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h != INVALID_HANDLE_VALUE) {
        DWORD written;
        WriteFile(h, buf, len, &written, nullptr);
        CloseHandle(h);
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved)
{
    return TRUE;
}
