//
//  Xanthorox-OFCrypt | Copyright (c) 2024-2026 Gary Senderson
//  Company: Xanthorox | All rights reserved. See LICENSE.
//

#pragma once
#include <windows.h>

// TLS callback executes BEFORE WinMain — early anti-debug via PEB checks.
// If a debugger is detected, g_TlsCallbackRan stays 0.
namespace TlsCallbackLoader
{
    bool Init(); // Returns true if TLS callback ran (no debugger detected)
}
