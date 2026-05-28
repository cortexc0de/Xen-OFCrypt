//
//  Xanthorox-OFCrypt | Copyright (c) 2024-2026 Gary Senderson
//  Company: Xanthorox | All rights reserved. See LICENSE.
//
//  CRT Stubs — minimal implementations for /NODEFAULTLIB linkage
//  memset, memcpy, memmove, __chkstk
//

#include <windows.h>

// Disable intrinsic declarations — we provide our own implementations
// for /NODEFAULTLIB linkage
#pragma function(memset, memcpy, memmove)

extern "C"
{
    // ═══ memset ═══
    void* __cdecl memset(void* dst, int val, size_t count)
    {
        unsigned char* ptr = (unsigned char*)dst;
        unsigned char fill = (unsigned char)val;
        while (count--) *ptr++ = fill;
        return dst;
    }

    // ═══ memcpy ═══
    void* __cdecl memcpy(void* dst, const void* src, size_t count)
    {
        unsigned char* d = (unsigned char*)dst;
        const unsigned char* s = (const unsigned char*)src;
        while (count--) *d++ = *s++;
        return dst;
    }

    // ═══ memmove ═══
    void* __cdecl memmove(void* dst, const void* src, size_t count)
    {
        unsigned char* d = (unsigned char*)dst;
        const unsigned char* s = (const unsigned char*)src;
        if (d < s) {
            while (count--) *d++ = *s++;
        } else if (d > s) {
            d += count;
            s += count;
            while (count--) *--d = *--s;
        }
        return dst;
    }

    // ═══ __chkstk ═══
    // Stack probe — OS handles guard pages, stub just returns
    // x64 MSVC uses double-underscore name
    void __cdecl __chkstk(void) {}
}
