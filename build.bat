@echo off
REM Build main.cpp with MSVC (x64). Finds the Visual Studio environment via
REM vswhere, so you do NOT need to start a "Developer Command Prompt" first.
setlocal

where cl >nul 2>&1 && goto :compile

set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" goto :nocl

"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath > "%TEMP%\_ldsa_vs.txt" 2>nul
set "VSINSTALL="
set /p VSINSTALL=<"%TEMP%\_ldsa_vs.txt"
del "%TEMP%\_ldsa_vs.txt" >nul 2>&1
if not defined VSINSTALL goto :nocl

call "%VSINSTALL%\VC\Auxiliary\Build\vcvars64.bat" >nul
goto :compile

:nocl
echo [!] No Visual Studio C++ toolset found. Open an "x64 Native Tools Command Prompt" and run:
echo     cl /std:c++17 /O2 /EHsc /MT main.cpp /link psapi.lib wintrust.lib crypt32.lib user32.lib
exit /b 1

:compile
cl /nologo /std:c++17 /O2 /EHsc /MT /W3 main.cpp /link psapi.lib wintrust.lib crypt32.lib user32.lib
if %errorlevel%==0 (
    echo.
    echo [+] Built: main.exe  ^(run as Administrator for the fullest reading^)
)
endlocal
