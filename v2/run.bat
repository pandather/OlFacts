@echo off
setlocal enabledelayedexpansion

rem ===================================================================
rem  OlFacts v2 launcher. Mark J. Kuebel. BUSL-1.1.
rem
rem    run.bat               start the bridge (generates certs on first run)
rem    run.bat selftest      verify TLS + delivery, then exit
rem
rem  Same flow as v1: check Python, install websockets if missing, generate
rem  certificates, self-test once on a fresh install, then serve. v2 listens
rem  on 8444 so both bridges can run side by side. The sniff model server must
rem  be up for scents to match card content; without it the bridge falls back
rem  to the fixed CORRECT scent and says so in its log.
rem ===================================================================

cd /d "%~dp0"

set "CERT=%~dp0certs\bridge-cert.pem"
set "KEY=%~dp0certs\bridge-key.pem"
set "MODE=%~1"

rem ---------------------------------------------------------------- python
set "PYTHON="
where py >nul 2>&1 && set "PYTHON=py"
if not defined PYTHON where python >nul 2>&1 && set "PYTHON=python"
if not defined PYTHON (
    echo ERROR: no Python launcher found. Install Python and try again.
    pause
    exit /b 1
)

rem ---------------------------------------------------------- dependencies
%PYTHON% -c "import websockets" >nul 2>&1
if errorlevel 1 (
    echo Installing websockets...
    %PYTHON% -m pip install -r requirements.txt
    if errorlevel 1 (
        echo ERROR: dependency install failed.
        pause
        exit /b 1
    )
)

rem ------------------------------------------------------------ first run?
set "FRESH=0"
if not exist "%CERT%" set "FRESH=1"
if not exist "%KEY%"  set "FRESH=1"

if "%FRESH%"=="0" goto :go

echo No certificates found -- generating them.
call make-cert.bat selfsigned
if errorlevel 1 (
    echo ERROR: certificate generation failed.
    pause
    exit /b 1
)
echo.
echo Trust %~dp0certs\bridge-cert.pem in Firefox before testing:
echo   about:preferences --^> Certificates --^> View Certificates --^> Authorities
echo   Import, then tick "Identifying websites".
echo.

:go
if /i "%MODE%"=="selftest" (
    %PYTHON% bridge.py --cert "%CERT%" --key "%KEY%" --selftest
    exit /b !errorlevel!
)

rem Self-test once on a fresh install so failures surface in this console,
rem not as silence inside the browser. Only meaningful against localhost.
if "%FRESH%"=="1" (
    echo First run: self-testing before serving...
    %PYTHON% bridge.py --cert "%CERT%" --key "%KEY%" --selftest
    if errorlevel 1 echo.
    if errorlevel 1 echo WARNING: self-test failed; continuing anyway, but the
    if errorlevel 1 echo browser will almost certainly fail to connect too.
)

echo Starting OlFacts v2 bridge on wss://127.0.0.1:8444/ -- Ctrl-C to stop.
%PYTHON% bridge.py --cert "%CERT%" --key "%KEY%"

pause
