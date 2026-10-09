@echo off
rem CTBU campus network auto login -- Windows diagnostic tool
chcp 65001 >nul
cd /d "%~dp0"

set "PYEXE=python"
where python >nul 2>nul || set "PYEXE=py"
where %PYEXE% >nul 2>nul || set "PYEXE="

if not defined PYEXE goto nopython

%PYEXE% campus_login.py --probe %*
echo.
echo Diagnostic report written to: diagnostic-report.txt
echo.
pause
exit /b 0

:nopython
echo [ERROR] Python 3 not found. Install from https://www.python.org/downloads/
echo.
pause
exit /b 3
