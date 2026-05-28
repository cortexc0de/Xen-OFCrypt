// test_payload_simple.cpp — Minimal kernel32-only test for RunPE
// Creates C:\temp\runpe_marker.txt and returns. No user32 dependency.

#include <windows.h>

int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {
    HANDLE h = CreateFileA("C:\\temp\\runpe_marker.txt",
        GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        const char* msg = "RunPE success! Payload executed.\n";
        DWORD wr = 0;
        WriteFile(h, msg, 28, &wr, NULL);
        CloseHandle(h);
    }
    return 0;
}
