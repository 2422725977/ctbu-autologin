@echo off
rem CTBU campus network auto login -- Windows launcher
chcp 65001 >nul
cd /d "%~dp0"

set "PYEXE=python"
where python >nul 2>nul || set "PYEXE=py"
where %PYEXE% >nul 2>nul || set "PYEXE="

if not defined PYEXE goto nopython

%PYEXE% campus_login.py %*
set RC=%errorlevel%

echo.
echo exit code = %RC%
if "%RC%"=="0" echo Result: network is OK ^(already online, or just logged in^).
if "%RC%"=="2" echo Result: not on campus network, nothing was done.
if "%RC%"=="3" echo Result: username/password missing in config.json.
if "%RC%"=="4" echo Result: credentials rejected, stopped to avoid locking the account.
if "%RC%"=="5" echo Result: captcha recognition failed too many times.
if "%RC%"=="6" echo Result: campus portal not found.
echo.
pause
exit /b %RC%

:nopython
echo [ERROR] Python 3 not found.
echo Install it from https://www.python.org/downloads/
echo and remember to tick "Add python.exe to PATH" during installation.
echo.
pause
exit /b 3
