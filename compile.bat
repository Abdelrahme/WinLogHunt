@echo off
echo Compiling Event Log Searcher...

REM Try to find Visual Studio installation
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if exist "%VSWHERE%" (
    for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do (
        set "VS_PATH=%%i"
    )
)

if defined VS_PATH (
    echo Found Visual Studio at: %VS_PATH%
    call "%VS_PATH%\VC\Auxiliary\Build\vcvars64.bat"
) else (
    echo Visual Studio not found, trying default paths...
    if exist "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" (
        call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
    ) else if exist "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat" (
        call "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat"
    ) else if exist "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat" (
        call "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
    ) else (
        echo Error: Visual Studio not found. Please install Visual Studio with C++ development tools.
        pause
        exit /b 1
    )
)

echo Compiling with cl.exe...
cl.exe /EHsc /std:c++17 /O2 /MT WinLogHunt.cpp /link psapi.lib advapi32.lib /OUT:WinLogHunt.exe

if %ERRORLEVEL% EQU 0 (
    echo.
    echo Compilation successful! Executable: WinLogHunt.exe
) else (
    echo.
    echo Compilation failed!
)

