@echo off
setlocal enabledelayedexpansion

rem ===================================================================
rem  OlFacts v2 loopback certificate. Mark J. Kuebel. BUSL-1.1.
rem
rem    make-cert.bat                 tiny CA + leaf (default)
rem    make-cert.bat selfsigned      single leaf, imported as its own authority
rem    make-cert.bat selfsigned 825  explicit validity in days
rem
rem  OpenSSL's -subj takes the form /type0=value0/type1=value1 with a LEADING
rem  SLASH. "CN=localhost" without it is rejected outright. Quotes are required
rem  because of the spaces in the CA subject; forward slashes inside them are
rem  passed through literally on Windows.
rem ===================================================================

set "MODE=%~1"
set "DAYS=%~2"
if "%DAYS%"=="" set "DAYS=825"

set "BASE=%~dp0certs"
if not exist "%BASE%" mkdir "%BASE%"

where openssl >nul 2>&1
if errorlevel 1 (
    echo ERROR: openssl not on PATH.
    echo Install Git for Windows ^(ships openssl^) or add it to PATH manually.
    exit /b 1
)

echo Generating OlFacts v2 certificates in %BASE%

if /i "%MODE%"=="selfsigned" goto :selfsigned

rem ---------------------------------------------------------------- CA + leaf
call :openssl req -x509 -newkey rsa:2048 -nodes ^
        -keyout "%BASE%\ca-key.pem" -out "%BASE%\ca-cert.pem" -days 3650 ^
        -subj "/CN=OlFacts Loopback CA" ^
        -addext "basicConstraints=critical,CA:TRUE" ^
        -addext "keyUsage=critical,keyCertSign,cRLSign"
if errorlevel 1 goto :failed

call :openssl req -newkey rsa:2048 -nodes ^
        -keyout "%BASE%\bridge-key.pem" -out "%BASE%\bridge.csr" ^
        -subj "/CN=localhost"
if errorlevel 1 goto :failed

rem Inline -extf is silently ignored by some builds; write a real extfile.
>"%BASE%\leaf-ext.cnf" echo [ext]
>>"%BASE%\leaf-ext.cnf" echo subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1
>>"%BASE%\leaf-ext.cnf" echo extendedKeyUsage=serverAuth

call :openssl x509 -req ^
        -in "%BASE%\bridge.csr" ^
        -CA "%BASE%\ca-cert.pem" -CAkey "%BASE%\ca-key.pem" -CAcreateserial ^
        -out "%BASE%\bridge-cert.pem" -days %DAYS% ^
        -extfile "%BASE%\leaf-ext.cnf" -extensions ext
if errorlevel 1 goto :failed

del /q "%BASE%\bridge.csr" "%BASE%\leaf-ext.cnf" >nul 2>&1
set "IMPORT=ca-cert.pem"
goto :report

:selfsigned
call :openssl req -x509 -newkey rsa:2048 -nodes ^
        -keyout "%BASE%\bridge-key.pem" -out "%BASE%\bridge-cert.pem" ^
        -days %DAYS% -subj "/CN=localhost" ^
        -addext "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1" ^
        -addext "basicConstraints=critical,CA:TRUE" ^
        -addext "keyUsage=critical,digitalSignature,keyEncipherment,keyCertSign" ^
        -addext "extendedKeyUsage=serverAuth"
if errorlevel 1 goto :failed
set "IMPORT=bridge-cert.pem"

:report
echo.
echo Certificates written:
dir /b "%BASE%\*.pem"
echo.
echo Import %BASE%\%IMPORT% into Firefox:
echo   about:preferences --^> Certificates --^> View Certificates
echo   Authorities tab --^> Import --^> tick "Identifying websites"
exit /b 0

:failed
rem A half-generated pair is worse than none: run.bat tests for both files and
rem would otherwise serve a key with no matching certificate.
del /q "%BASE%\*.pem" "%BASE%\*.cnf" >nul 2>&1
echo ERROR: openssl failed. Partial output removed; check the text above.
exit /b 1

rem :openssl runs the tool without ^-continuation eating the arguments.
:openssl
call openssl %*
exit /b %errorlevel%
