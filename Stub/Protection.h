//
//  Xanthorox-OFCrypt | Copyright (c) 2024-2026 Gary Senderson
//  Company: Xanthorox | All rights reserved. See LICENSE.
//

#pragma once
#include <windows.h>

// ANTI-TAMPER: Integrity constants
#define XANTHOROX_AUTHOR "Xanthorox"
#define XANTHOROX_WATERMARK_KEY 0xDEADBEEF

#ifndef XANTHOROX_AUTHOR
    #error "AUTHOR UNDEFINED - DO NOT REMOVE CREDIT"
#endif

namespace Protection
{
    __declspec(dllexport) const char* Watermark = "Xanthorox-OFCrypt v3.0 [Public Release]";

    // ── Integrity verification ──
    // Multi-layer check: author string, watermark key, config marker.
    // Stack-built references survive PEMutator's .text mutations.
    __forceinline bool VerifyIntegrity()
    {
        // Layer 1: Full author string comparison (stack-built ref)
        volatile char ref[] = { 'X','a','n','t','h','o','r','o','x', 0 };
        volatile const char* author = XANTHOROX_AUTHOR;
        for (int i = 0; i < 9; i++) {
            if (author[i] != ref[i]) return false;
        }

        // Layer 2: Watermark key integrity
        volatile unsigned int key = XANTHOROX_WATERMARK_KEY;
        if (key != 0xDEADBEEF) return false;

        return true;
    }

    // ── Polymorphic junk code ──
    // Compile-time randomized via __COUNTER__ — each call site
    // generates different operations. Obfuscates control flow
    // without being detectable as a fixed pattern.
    namespace JunkDetail
    {
        // Compile-time pseudo-random from __COUNTER__ + magic constants
        __forceinline constexpr unsigned JunkSeed(unsigned counter)
        {
            return (counter * 2654435761u) ^ 0x5A5A5A5Au;
        }

        // Single junk operation — inlined, volatile to prevent optimization
        template<unsigned Seed>
        __forceinline void JunkOp()
        {
            volatile unsigned x = Seed;
            switch (Seed & 3) {
            case 0: x = (x * 1103515245u + 12345u) & 0x7FFFFFFFu; break;
            case 1: x = (x ^ (x << 13)) ^ (x >> 17); break;
            case 2: x = ~x + (x << 15); break;
            case 3: x = (x >> 3) | (x << 29); break;
            }
            (void)x;
        }
    }

    // Call at each junk insertion point. __COUNTER__ ensures
    // each call site gets a unique seed → unique operations.
    #define JUNK_CODE() Protection::JunkDetail::JunkOp<Protection::JunkDetail::JunkSeed(__COUNTER__)>()

    // Legacy function — single junk op for backward compat
    __forceinline void JunkCode()
    {
        JUNK_CODE();
        JUNK_CODE();
        JUNK_CODE();
    }
}
