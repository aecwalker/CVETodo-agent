@echo off
REM CVETodo Agent Windows Build Script

echo Building CVETodo Agent for Windows...

REM Create build directory if it doesn't exist
if not exist build mkdir build

REM Set build variables
set BINARY_NAME=cvetodo-agent
set VERSION=dev
for /f %%i in ('git rev-parse --short HEAD 2^>nul') do set COMMIT=%%i
if "%COMMIT%"=="" set COMMIT=unknown
for /f "tokens=*" %%i in ('powershell -Command "Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ'"') do set DATE=%%i

REM Build flags
set LDFLAGS=-ldflags "-X main.version=%VERSION% -X main.commit=%COMMIT% -X main.date=%DATE%"

REM Build the agent
echo Building with flags: %LDFLAGS%
go build %LDFLAGS% -o build/%BINARY_NAME%.exe ./cmd/agent

if %ERRORLEVEL% == 0 (
    echo.
    echo Build successful! Created: build/%BINARY_NAME%.exe
    echo.
    echo To initialize configuration: build\%BINARY_NAME%.exe config init
    echo To run a scan: build\%BINARY_NAME%.exe scan
) else (
    echo.
    echo Build failed with error code %ERRORLEVEL%
    exit /b %ERRORLEVEL%
) 