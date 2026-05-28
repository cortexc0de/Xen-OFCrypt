#pragma once
#include <windows.h>

// IAT-linked diagnostic logger — bypasses CRC32C resolution.
// Uses direct kernel32.lib imports so it works even when
// CRC32C API resolution chain is broken or uninitialized.
// Writes to %USERPROFILE%\stub_trace.log

namespace IATLog {
    __forceinline void Write(const char* msg) {
        char logPath[MAX_PATH] = {};
        DWORD n = GetEnvironmentVariableA("USERPROFILE", logPath, MAX_PATH);
        if (n > 0 && n < MAX_PATH - 24) {
            size_t t = n; logPath[t++] = '\\';
            const char* fn = "stub_trace.log"; size_t f = 0;
            while (fn[f] && t < MAX_PATH-1) logPath[t++] = fn[f++];
            logPath[t] = 0;
            HANDLE h = CreateFileA(logPath, GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            if (h != INVALID_HANDLE_VALUE) {
                SetFilePointer(h, 0, NULL, FILE_END);
                DWORD w = 0; size_t len = 0; while (msg[len]) len++;
                WriteFile(h, msg, (DWORD)len, &w, NULL);
                WriteFile(h, "\r\n", 2, &w, NULL);
                CloseHandle(h);
            }
        }
    }

    __forceinline void WriteHex(const char* label, ULONG_PTR val) {
        char buf[128];
        size_t i = 0;
        while (label[i] && i < 80) { buf[i] = label[i]; i++; }
        buf[i++] = '='; buf[i++] = '0'; buf[i++] = 'x';
        char hex[17]; int h = 0;
        if (val == 0) { hex[h++] = '0'; }
        else { while (val && h < 16) { int d = (int)(val & 0xF); hex[h++] = (d < 10) ? ('0'+d) : ('a'+d-10); val >>= 4; } }
        for (int j = h-1; j >= 0; j--) buf[i++] = hex[j];
        buf[i] = 0;
        Write(buf);
    }
}
