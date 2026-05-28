@echo off
call "D:\Development\Visual Studio\Community\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul 2>&1
cd /d D:\Development\projects\Malware\crypters\Xen-OFCrypt\build\e2e_test
echo === Building test_payload.exe ===
cl.exe /nologo /W4 /O2 /MT /GS- /Zl /DNDEBUG /D_WIN64 /EHs-c- /GR- /utf-8 /c /Fo"obj\test_payload.obj" "test_payload.cpp"
if errorlevel 1 (
    echo TEST_PAYLOAD_COMPILE_FAILED
    exit /b 1
)
link.exe /nologo /SUBSYSTEM:WINDOWS /NODEFAULTLIB /ENTRY:WinMain /OUT:"bin\test_payload.exe" obj\test_payload.obj kernel32.lib user32.lib
if errorlevel 1 (
    echo TEST_PAYLOAD_LINK_FAILED
    exit /b 1
)
echo TEST_PAYLOAD_BUILD_OK
dir bin\test_payload.exe
