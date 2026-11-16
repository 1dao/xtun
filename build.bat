@echo off
setlocal EnableExtensions EnableDelayedExpansion
cd /d "%~dp0"

set "MODE=release"
set "TARGET=all"
set "JOBS=8"
:parse_args
if "%~1"=="" goto args_ready
set "ARG=%~1"
    if /I "!ARG:~0,2!"=="-j" (
        set "JOBS=!ARG:~2!"
    ) else (
    if /I "%~1"=="release" (set "MODE=release") else if /I "%~1"=="debug" (set "MODE=debug") else if /I "%~1"=="test" (set "TARGET=test") else if /I "%~1"=="all" (set "TARGET=all") else if /I "%~1"=="gui" (set "TARGET=gui") else if /I "%~1"=="console" (set "TARGET=console") else (
        echo Usage: build.bat [release^|debug] [all^|gui^|console^|test] [-jN]
        exit /b 1
    )
    )
shift
goto parse_args
:args_ready
REM Validate before passing the value to cl's /MP option.
set "BAD_JOBS="
for /f "delims=0123456789" %%N in ("%JOBS%") do set "BAD_JOBS=1"
if not defined JOBS set "BAD_JOBS=1"
if defined BAD_JOBS goto invalid_jobs
if %JOBS% LSS 1 goto invalid_jobs
if %JOBS% GTR 65536 goto invalid_jobs
echo [INFO] Parallel compile jobs=%JOBS%

REM Like core/build.bat, compile all dependencies from source with MSVC.
REM /MT also embeds the C runtime; Wintun remains a separate signed DLL.
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" set "VSWHERE=%ProgramFiles%\Microsoft Visual Studio\Installer\vswhere.exe"
if /I not "%VSCMD_ARG_TGT_ARCH%"=="x64" (
    if not exist "!VSWHERE!" (
        echo [ERROR] Install Visual Studio or Build Tools with the C++ x64 tools.
        exit /b 1
    )
    set "VCVARS="
    for /f "usebackq tokens=*" %%P in (`"!VSWHERE!" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -find VC\Auxiliary\Build\vcvarsall.bat`) do set "VCVARS=%%P"
    if not defined VCVARS (
        echo [ERROR] MSVC x64 tools not found.
        exit /b 1
    )
    call "!VCVARS!" x64
    if errorlevel 1 exit /b 1
)

set "OBJ=build\msvc\%MODE%"
if not exist "%OBJ%" mkdir "%OBJ%"
if not exist bin mkdir bin
set "FLAGS=/nologo /TC /W3 /utf-8 /std:c11 /experimental:c11atomics /DWIN32_LEAN_AND_MEAN /DWINVER=0x0A00 /D_WIN32_WINNT=0x0A00 /D_CRT_SECURE_NO_WARNINGS /DXNET_WITH_UDP=1 /DXMACRO_USE_RPMALLOC=0 /Icore /Icore\3rd\mbedtls3\include /Isrc"
set "LINKFLAGS=/nologo /INCREMENTAL:NO"
set "FLAGS=%FLAGS% /MP%JOBS% /FS"
if "%MODE%"=="debug" (
    set "FLAGS=%FLAGS% /Od /Zi /MTd /DDEBUG /Fd%OBJ%\"
    set "LINKFLAGS=%LINKFLAGS% /DEBUG"
) else (
    set "FLAGS=%FLAGS% /O2 /MT /DNDEBUG"
)
set "LIBS=ws2_32.lib bcrypt.lib advapi32.lib iphlpapi.lib winmm.lib"
set "CORE_OBJS="
set "SOURCES="
for %%F in (xargs xudp xpoll xsock xlog xdaemon) do (
    set "SOURCES=!SOURCES! core\%%F.c"
    set "CORE_OBJS=!CORE_OBJS! %OBJ%\core\%%F.obj"
)
call :compile_group "%OBJ%\core" %SOURCES%
if errorlevel 1 exit /b 1
set "MBED_OBJS="
set "SOURCES="
for %%F in (core\3rd\mbedtls3\library\*.c) do (
    set "SOURCES=!SOURCES! %%F"
    set "MBED_OBJS=!MBED_OBJS! %OBJ%\mbed\%%~nF.obj"
)
call :compile_group "%OBJ%\mbed" %SOURCES%
if errorlevel 1 exit /b 1
set "APP_OBJS="
set "SOURCES="
for %%F in (config tunnel platform xdtls) do (
    set "SOURCES=!SOURCES! src\%%F.c"
    set "APP_OBJS=!APP_OBJS! %OBJ%\app\%%F.obj"
)
call :compile_group "%OBJ%\app" %SOURCES%
if errorlevel 1 exit /b 1
call :compile src\main.c "%OBJ%\main.obj"
if errorlevel 1 exit /b 1
if not "%TARGET%"=="gui" (
    link %LINKFLAGS% /OUT:bin\xtun.exe %OBJ%\main.obj %APP_OBJS% %CORE_OBJS% %MBED_OBJS% %LIBS%
    if errorlevel 1 exit /b 1
)
if not "%TARGET%"=="console" (
    if not exist 3rd\raylib\src\raylib.h goto missing_ui
    if not exist 3rd\raygui\src\raygui.h goto missing_ui
    set "SAVED_FLAGS=!FLAGS!"
    set "FLAGS=!FLAGS! /Dmain=xt_cli_main"
    call :compile src\main.c "%OBJ%\ui_main.obj"
    if errorlevel 1 exit /b 1
    set "FLAGS=!SAVED_FLAGS! /I3rd\raylib\src /I3rd\raylib\src\external\glfw\include /DPLATFORM_DESKTOP /DGRAPHICS_API_OPENGL_33"
    set "RAY_OBJS="
    set "SOURCES="
    for %%F in (rcore rshapes rtextures rtext rglfw rmodels raudio) do (
        set "SOURCES=!SOURCES! 3rd\raylib\src\%%F.c"
        set "RAY_OBJS=!RAY_OBJS! %OBJ%\ray\%%F.obj"
    )
    call :compile_group "%OBJ%\ray" !SOURCES!
    if errorlevel 1 exit /b 1
    set "FLAGS=!SAVED_FLAGS! /I3rd\raylib\src /I3rd\raygui\src"
    set "UI_OBJS="
    set "SOURCES="
    for %%F in (client process tray client_config) do (
        set "SOURCES=!SOURCES! ui\%%F.c"
        set "UI_OBJS=!UI_OBJS! %OBJ%\ui\%%F.obj"
    )
    call :compile_group "%OBJ%\ui" !SOURCES!
    if errorlevel 1 exit /b 1
    set "FLAGS=!SAVED_FLAGS!"
    rc /nologo /Iui /fo "%OBJ%\xtun.res" ui\xtun.rc
    if errorlevel 1 exit /b 1
    link %LINKFLAGS% /SUBSYSTEM:WINDOWS /ENTRY:mainCRTStartup /OUT:bin\xtun-gui.exe !UI_OBJS! %OBJ%\ui_main.obj %APP_OBJS% %CORE_OBJS% %MBED_OBJS% !RAY_OBJS! %OBJ%\xtun.res %LIBS% opengl32.lib gdi32.lib shell32.lib user32.lib
    if errorlevel 1 exit /b 1
    type ui\vendor\*LICENSE.txt > bin\raygui-notices.txt
    if errorlevel 1 exit /b 1
    echo [INFO] Built bin\xtun-gui.exe with embedded tunnel and static CRT ^(%MODE%^).
)
if "%TARGET%"=="test" (
    REM Tests use assert for checks and setup, including release builds.
    set "FLAGS=!FLAGS! /UNDEBUG"
    for %%T in (dtls arq platform_windows) do (
        call :compile "tests\%%T_test.c" "%OBJ%\%%T_test.obj"
        if errorlevel 1 exit /b 1
        set "TEST_OBJS=!APP_OBJS!"
        if "%%T"=="arq" set "TEST_OBJS=%OBJ%\app\config.obj %OBJ%\app\platform.obj %OBJ%\app\xdtls.obj"
        if "%%T"=="platform_windows" set "TEST_OBJS="
        link %LINKFLAGS% /OUT:bin\%%T_test.exe %OBJ%\%%T_test.obj !TEST_OBJS! %CORE_OBJS% %MBED_OBJS% %LIBS%
        if errorlevel 1 exit /b 1
        bin\%%T_test.exe
        if errorlevel 1 exit /b 1
    )
)
powershell -NoProfile -Command "Get-ChildItem -LiteralPath 'build' -Force | Remove-Item -Recurse -Force -ErrorAction Stop"
if errorlevel 1 exit /b 1
if not "%TARGET%"=="gui" echo [INFO] Built bin\xtun.exe with static CRT ^(%MODE%^).
exit /b 0

:missing_ui
echo [ERROR] Missing UI submodules. Run: git submodule update --init --recursive
exit /b 1

:compile
cl %FLAGS% /c "%~1" /Fo"%~2"
exit /b %errorlevel%

:compile_group
REM /MP requires multiple source files in a single cl invocation.
set "GROUP_DIR=%~1"
if not exist "%GROUP_DIR%" mkdir "%GROUP_DIR%"
set "GROUP_SOURCES="
shift
:group_sources
if "%~1"=="" goto group_ready
set "GROUP_SOURCES=%GROUP_SOURCES% "%~1""
shift
goto group_sources
:group_ready
cl %FLAGS% /c %GROUP_SOURCES% /Fo"%GROUP_DIR%\\"
exit /b %errorlevel%

:invalid_jobs
echo [ERROR] jobs must be an integer from 1 to 65536.
exit /b 1
