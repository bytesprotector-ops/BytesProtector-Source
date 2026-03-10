@echo off
echo( ____ ___  _ _____ _____ ____  ____  ____  ____ _____ _____ ____ _____ ____  ____ 
echo(/  __\\  \///__ __Y  __// ___\/  __\/  __\/  _ Y__ __Y  __//   _Y__ __Y  _ \/  __\
echo(^| ^| // \  /   / \ ^|  \  ^|    \^|  \/^|^|  \/^|^| / \^| / \ ^|  \  ^|  /   / \ ^| / \^|^|  \/^|
echo(^| ^|_\\ / /    ^| ^| ^|  /_ \___ ^|^|  __/^|    /^| \_/^| ^| ^| ^|  /_ ^|  \_  ^| ^| ^| \_/^|^|    /
echo(\____//_/     \_/ \____\\____/\_/   \_/\_\\____/ \_/ \____\\____/ \_/ \____/\_/\_\
echo(                                                                                  
echo(               ____  _     _  _     ____    ____  ____ _____ ____ _               
echo(              /  __\/ \ /\/ \/ \   /  _ \  /  __\/  _ Y__ __Y   _Y \ /^|          
echo(              ^| ^| //^| ^| ^|^|^| ^|^| ^|   ^| ^| \^|  ^| ^| //^| ^| \^| / \ ^|  / ^| ^|_^|^|          
echo(              ^| ^|_\\^| \_/^|^| ^|^| ^|_/\^| ^|_/^|  ^| ^|_\\^| ^|-^|^| ^| ^| ^|  \_^| ^| ^|^|          
echo(              \____/\____/\_/\____/\____/  \____/\_/ \^| \_/ \____^|_/ \^|          
echo(
echo  BytesProtector Electron  ^|  Build Script
echo  ==========================================
echo.

REM ── 1. npm install ────────────────────────────────────────────────────────
echo [1/5] npm install...
call npm install
if errorlevel 1 (
    echo [WARN] npm install had errors - continuing anyway
) else (
    echo [OK] npm deps installed
)
echo.

REM ── 2. Python deps ────────────────────────────────────────────────────────
echo [2/5] Python deps...
where python >nul 2>&1
if %errorlevel%==0 (
    python -m pip install watchdog --quiet --disable-pip-version-check
    if errorlevel 1 (
        echo [WARN] watchdog install failed - endpoint protection may be limited
    ) else (
        echo [OK] Python deps ready
    )
) else (
    echo [WARN] Python not found - install Python 3.10+ from https://python.org
)
echo.

REM ── 3. C engine ───────────────────────────────────────────────────────────
echo [3/5] Building C heuristic engine...
set GCC_FOUND=0

where gcc >nul 2>&1
if %errorlevel%==0 (
    set GCC_FOUND=1
    set GCC_EXE=gcc
    goto :do_gcc
)

REM Search common MinGW/MSYS2 locations
if exist "C:\msys64\mingw64\bin\gcc.exe"        set GCC_EXE=C:\msys64\mingw64\bin\gcc.exe   & set GCC_FOUND=1 & goto :do_gcc
if exist "C:\msys64\mingw32\bin\gcc.exe"        set GCC_EXE=C:\msys64\mingw32\bin\gcc.exe   & set GCC_FOUND=1 & goto :do_gcc
if exist "C:\msys32\mingw32\bin\gcc.exe"        set GCC_EXE=C:\msys32\mingw32\bin\gcc.exe   & set GCC_FOUND=1 & goto :do_gcc
if exist "C:\mingw64\bin\gcc.exe"               set GCC_EXE=C:\mingw64\bin\gcc.exe          & set GCC_FOUND=1 & goto :do_gcc
if exist "C:\mingw32\bin\gcc.exe"               set GCC_EXE=C:\mingw32\bin\gcc.exe          & set GCC_FOUND=1 & goto :do_gcc
if exist "C:\MinGW\bin\gcc.exe"                 set GCC_EXE=C:\MinGW\bin\gcc.exe            & set GCC_FOUND=1 & goto :do_gcc
if exist "C:\TDM-GCC-64\bin\gcc.exe"            set GCC_EXE=C:\TDM-GCC-64\bin\gcc.exe       & set GCC_FOUND=1 & goto :do_gcc
if exist "C:\TDM-GCC-32\bin\gcc.exe"            set GCC_EXE=C:\TDM-GCC-32\bin\gcc.exe       & set GCC_FOUND=1 & goto :do_gcc

echo [SKIP] gcc not found - C engine disabled ^(Python fallback is active, fully functional^)
echo        To enable: install WinLibs ^(https://winlibs.com^) or MSYS2 ^(https://msys2.org^)
goto :after_gcc

:do_gcc
echo [..] gcc found at %GCC_EXE% - compiling...
"%GCC_EXE%" -O2 -shared -lm -o backend\c\libheuristic.dll backend\c\heuristic_engine.c
if errorlevel 1 (
    echo [WARN] C engine compile failed
) else (
    echo [OK] C engine built - libheuristic.dll
)

:after_gcc
echo.

REM ── 4. Rust engine ────────────────────────────────────────────────────────
echo [4/5] Building Rust hash engine...
where cargo >nul 2>&1
if %errorlevel%==0 (
    cd backend\rust
    cargo build --release
    if errorlevel 1 (
        echo [WARN] Rust build failed - Python fallback active
    ) else (
        echo [OK] Rust engine built
    )
    cd ..\..
) else (
    echo [SKIP] cargo not found - Rust engine disabled ^(Python fallback active^)
    echo        Install Rust: https://rustup.rs
)
echo.

REM ── 5. Summary ────────────────────────────────────────────────────────────
echo [5/5] Done!
echo.
echo  ==========================================
if %GCC_FOUND%==1 (
    echo   C engine  : ENABLED
) else (
    echo   C engine  : Python fallback ^(fully functional^)
)
echo.
echo   npm start          - launch BytesProtector
echo   npm run build      - package as installer ^(.exe^)
echo   npm run pack       - package without installer
echo  ==========================================
echo.
pause
