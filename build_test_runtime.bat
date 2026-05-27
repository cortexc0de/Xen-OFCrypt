@echo off
call "D:\Development\Visual Studio\Community\VC\Auxiliary\Build\vcvarsall.bat" x64
if errorlevel 1 (
    echo ERROR: vcvarsall.bat failed
    exit /b 1
)

set STUBDIR=Stub
set CFLAGS=/nologo /W4 /O2 /MT /DNDEBUG /D_WIN64 /EHs-c- /GR- /utf-8

REM Compile stub modules needed by test
cl.exe %CFLAGS% /c /Fo"build\obj\ApiResolver_test.obj" "%STUBDIR%\ApiResolver.cpp"
if errorlevel 1 exit /b 1

cl.exe %CFLAGS% /c /Fo"build\obj\PureCrypto_test.obj" "%STUBDIR%\PureCrypto.cpp"
if errorlevel 1 exit /b 1

cl.exe %CFLAGS% /c /Fo"build\obj\Syscall_test.obj" "%STUBDIR%\Syscall.cpp"
if errorlevel 1 exit /b 1

cl.exe %CFLAGS% /c /Fo"build\obj\GadgetPool_test.obj" "%STUBDIR%\GadgetPool.cpp"
if errorlevel 1 exit /b 1

cl.exe %CFLAGS% /c /Fo"build\obj\Hotpatch_test.obj" "%STUBDIR%\Hotpatch.cpp"
if errorlevel 1 exit /b 1

cl.exe %CFLAGS% /c /Fo"build\obj\CrtStubs_test.obj" "%STUBDIR%\CrtStubs.cpp"
if errorlevel 1 exit /b 1

REM Assemble MASM
ml64.exe /c /nologo /Fo"build\obj\IndirectSyscall_test.obj" "%STUBDIR%\IndirectSyscall.asm"
if errorlevel 1 exit /b 1

ml64.exe /c /nologo /Fo"build\obj\StackSpoofAsm_test.obj" "%STUBDIR%\StackSpoof.asm"
if errorlevel 1 exit /b 1

REM Compile test driver (console mode, with CRT)
cl.exe %CFLAGS% /c /Fo"build\obj\test_runtime.obj" test_runtime.cpp
if errorlevel 1 exit /b 1

REM Link as console app with normal CRT
link.exe /nologo /SUBSYSTEM:CONSOLE /OUT:"test_runtime.exe" ^
    build\obj\test_runtime.obj ^
    build\obj\ApiResolver_test.obj ^
    build\obj\PureCrypto_test.obj ^
    build\obj\Syscall_test.obj ^
    build\obj\GadgetPool_test.obj ^
    build\obj\Hotpatch_test.obj ^
    build\obj\CrtStubs_test.obj ^
    build\obj\IndirectSyscall_test.obj ^
    build\obj\StackSpoofAsm_test.obj ^
    kernel32.lib user32.lib ntdll.lib bcrypt.lib advapi32.lib ole32.lib mscoree.lib

if errorlevel 1 (
    echo LINK FAILED
    exit /b 1
)

echo.
echo === BUILD SUCCESS ===
echo Output: test_runtime.exe
