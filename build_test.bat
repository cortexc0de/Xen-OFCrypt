@echo off
setlocal enabledelayedexpansion

REM Test Runner Build — uses console subsystem for printf output

for /f "usebackq tokens=*" %%i in (`"C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe" -latest -property installationPath`) do set VSPATH=%%i
if not defined VSPATH ( echo ERROR: VS not found & exit /b 1 )

call "%VSPATH%\VC\Auxiliary\Build\vcvarsall.bat" x64

set STUBDIR=Stub
set OBJDIR=build\obj
set OUTDIR=build\out

REM Compile all needed .cpp files for test runner
set CFLAGS=/nologo /O2 /MT /DNDEBUG /D_WIN64 /EHs-c- /GR- /utf-8

echo [TEST BUILD] Compiling...

REM Assemble MASM
ml64.exe /c /nologo /Fo"%OBJDIR%\IndirectSyscall.obj" "%STUBDIR%\IndirectSyscall.asm"
ml64.exe /c /nologo /Fo"%OBJDIR%\StackSpoofAsm.obj" "%STUBDIR%\StackSpoof.asm"

REM Compile C++ (need more files for test deps)
for %%F in (ApiResolver PureCrypto Syscall KnownDlls GadgetPool StackSpoof PatchlessBypass VehDispatcher Hotpatch Unhook CrtStubs GuardPage) do (
    cl.exe %CFLAGS% /c /Fo"%OBJDIR%\%%F.obj" "%STUBDIR%\%%F.cpp"
)

REM Compile TestRunner with console subsystem
cl.exe %CFLAGS% /c /Fo"%OBJDIR%\TestRunner.obj" "%STUBDIR%\TestRunner.cpp"

REM Link as console app (NOT /NODEFAULTLIB — we want CRT for printf)
echo [TEST BUILD] Linking...
set OBJFILES=
for %%F in (%OBJDIR%\IndirectSyscall.obj %OBJDIR%\StackSpoofAsm.obj %OBJDIR%\ApiResolver.obj %OBJDIR%\PureCrypto.obj %OBJDIR%\Syscall.obj %OBJDIR%\KnownDlls.obj %OBJDIR%\GadgetPool.obj %OBJDIR%\StackSpoof.obj %OBJDIR%\PatchlessBypass.obj %OBJDIR%\VehDispatcher.obj %OBJDIR%\Hotpatch.obj %OBJDIR%\Unhook.obj %OBJDIR%\CrtStubs.obj %OBJDIR%\GuardPage.obj %OBJDIR%\TestRunner.obj) do (
    set OBJFILES=!OBJFILES! %%F
)

link.exe /nologo /SUBSYSTEM:CONSOLE /OUT:"%OUTDIR%\test_runner.exe" %OBJFILES% kernel32.lib user32.lib advapi32.lib ntdll.lib

if errorlevel 1 (
    echo ERROR: Linking failed
    exit /b 1
)

echo [TEST BUILD] SUCCESS: %OUTDIR%\test_runner.exe
