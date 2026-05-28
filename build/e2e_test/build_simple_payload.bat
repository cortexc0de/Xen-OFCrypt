@echo off
call "D:\Development\Visual Studio\Community\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul 2>&1
cd /d D:\Development\projects\Malware\crypters\Xen-OFCrypt\build\e2e_test
echo === Building test_payload_simple.exe ===
cl.exe /nologo /W4 /O2 /MT /GS- /Zl /DNDEBUG /D_WIN64 /EHs-c- /GR- /utf-8 /c /Fo"obj\test_payload_simple.obj" "test_payload_simple.cpp"
if errorlevel 1 (
    echo SIMPLE_COMPILE_FAILED
    exit /b 1
)
link.exe /nologo /SUBSYSTEM:WINDOWS /NODEFAULTLIB /ENTRY:WinMain /OUT:"bin\test_payload_simple.exe" obj\test_payload_simple.obj kernel32.lib
if errorlevel 1 (
    echo SIMPLE_LINK_FAILED
    exit /b 1
)
echo SIMPLE_BUILD_OK
dir bin\test_payload_simple.exe
