// test_payload.cpp — Simple Win32 GUI app for RunPE verification
// Creates C:\temp\runpe_marker.txt, shows a MessageBox, then exits.
// This proves the hollowed PE actually executes its code.

#include <windows.h>

void WriteMarker() {
    HANDLE h = CreateFileA("C:\\temp\\runpe_marker.txt",
        GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        const char* msg = "RunPE success! Payload executed.\n";
        DWORD wr = 0;
        WriteFile(h, msg, 28, &wr, NULL);
        CloseHandle(h);
    }
}

int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {
    WriteMarker();
    MessageBoxA(NULL, "RunPE payload executed!", "Test", MB_OK);
    return 0;
}
