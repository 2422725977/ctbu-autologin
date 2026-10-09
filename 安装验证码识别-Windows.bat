@echo off
rem One-click installer for automatic captcha recognition (ddddocr) -- Windows
rem Creates a .venv in this folder; campus_login.py will auto-switch to it.
chcp 65001 >nul
cd /d "%~dp0"

echo ================================================================
echo   Install automatic captcha recognition (ddddocr)
echo ================================================================
echo   About 50MB download. Requires real internet access
echo   (it will NOT work while the campus network is unauthenticated).
echo ================================================================
echo.

set "PYEXE=python"
where python >nul 2>nul || set "PYEXE=py"
where %PYEXE% >nul 2>nul || set "PYEXE="
if not defined PYEXE goto nopython

if exist ".venv\Scripts\python.exe" (
    echo [1/3] Reusing existing .venv
) else (
    echo [1/3] Creating .venv ...
    %PYEXE% -m venv .venv
    if errorlevel 1 goto venvfail
)

echo [2/3] Upgrading pip ...
.venv\Scripts\python.exe -m pip install --upgrade pip -q

echo [3/3] Installing ddddocr ^(this may take a few minutes^) ...
.venv\Scripts\python.exe -m pip install ddddocr

echo.
.venv\Scripts\python.exe -c "import ddddocr" >nul 2>nul
if errorlevel 1 (
    echo ================================================================
    echo   FAILED. Check that pypi.org is reachable, then rerun.
    echo   Not installed is fine too: the program will ask you to
    echo   type the captcha manually instead.
    echo ================================================================
) else (
    echo ================================================================
    echo   OK! Captcha will be recognized automatically from now on.
    echo ================================================================
)
echo.
pause
exit /b 0

:venvfail
echo [ERROR] Failed to create .venv
pause
exit /b 1

:nopython
echo [ERROR] Python 3 not found. Install from https://www.python.org/downloads/
echo         and tick "Add python.exe to PATH".
pause
exit /b 3
