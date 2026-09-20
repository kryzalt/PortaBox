@echo off
setlocal

if not exist main.cpp (
    echo [ERROR] main.cpp not found in the current directory.
    pause
    exit /b 1
)

if not exist NetworkSandbox.cpp (
    echo [ERROR] NetworkSandbox.cpp not found in the current directory.
    pause
    exit /b 1
)

if "%~1"=="BUILD_X86" goto :build_x86
if "%~1"=="BUILD_X64" goto :build_x64

mkdir bin_x86 2>nul
mkdir bin_x64 2>nul

echo ========================================================
echo [1/2] Building x86 [32-bit] (version / winmm / dwmapi / mscoree / d3d9 / dxgi)...
echo ========================================================
cmd /c "%~f0" BUILD_X86
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] x86 build failed.
    pause
    exit /b 1
)

echo.
echo ========================================================
echo [2/2] Building x64 [64-bit] (version / winmm / dwmapi / mscoree / d3d9 / dxgi)...
echo ========================================================
cmd /c "%~f0" BUILD_X64
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] x64 build failed.
    pause
    exit /b 1
)

del bin_x86\*.obj bin_x86\*.exp bin_x86\*.lib bin_x64\*.obj bin_x64\*.exp bin_x64\*.lib 2>nul

echo.
echo ========================================================
echo Build complete!
echo Generated in bin_x86 and bin_x64:
echo  - version.dll
echo  - winmm.dll
echo  - dwmapi.dll
echo  - mscoree.dll
echo  - d3d9.dll
echo  - dxgi.dll
echo ========================================================
pause
exit /b 0

:build_x86
if exist "vcvars32.bat" (
    call "vcvars32.bat"
) else if exist "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars32.bat" (
    call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars32.bat"
) else if exist "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars32.bat" (
    call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars32.bat"
) else if exist "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars32.bat" (
    call "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars32.bat"
)

cl.exe /nologo /LD /O2 /EHsc /D_CRT_SECURE_NO_WARNINGS main.cpp NetworkSandbox.cpp /Fe:bin_x86\version.dll /Fo:bin_x86\ /link /MACHINE:X86 kernel32.lib user32.lib advapi32.lib shell32.lib shlwapi.lib ole32.lib comctl32.lib ws2_32.lib

if %ERRORLEVEL% EQU 0 (
    copy /y bin_x86\version.dll bin_x86\winmm.dll >nul
    copy /y bin_x86\version.dll bin_x86\dwmapi.dll >nul
    copy /y bin_x86\version.dll bin_x86\mscoree.dll >nul
    copy /y bin_x86\version.dll bin_x86\d3d9.dll >nul
    copy /y bin_x86\version.dll bin_x86\dxgi.dll >nul
    echo [SUCCESS] bin_x86: version.dll, winmm.dll, dwmapi.dll, mscoree.dll, d3d9.dll, dxgi.dll created.
    exit /b 0
) else (
    exit /b 1
)

:build_x64
if exist "vcvars64.bat" (
    call "vcvars64.bat"
) else if exist "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" (
    call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
) else if exist "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" (
    call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
) else if exist "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat" (
    call "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat"
)

cl.exe /nologo /LD /O2 /EHsc /D_CRT_SECURE_NO_WARNINGS main.cpp NetworkSandbox.cpp /Fe:bin_x64\version.dll /Fo:bin_x64\ /link /MACHINE:X64 kernel32.lib user32.lib advapi32.lib shell32.lib shlwapi.lib ole32.lib comctl32.lib ws2_32.lib

if %ERRORLEVEL% EQU 0 (
    copy /y bin_x64\version.dll bin_x64\winmm.dll >nul
    copy /y bin_x64\version.dll bin_x64\dwmapi.dll >nul
    copy /y bin_x64\version.dll bin_x64\mscoree.dll >nul
    copy /y bin_x64\version.dll bin_x64\d3d9.dll >nul
    copy /y bin_x64\version.dll bin_x64\dxgi.dll >nul
    echo [SUCCESS] bin_x64: version.dll, winmm.dll, dwmapi.dll, mscoree.dll, d3d9.dll, dxgi.dll created.
    exit /b 0
) else (
    exit /b 1
)
