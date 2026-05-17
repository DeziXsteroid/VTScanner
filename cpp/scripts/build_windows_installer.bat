@echo off
setlocal enabledelayedexpansion

set ROOT_DIR=%~dp0\..\..
set ROOT_DIR=%ROOT_DIR:\/=%
for %%I in ("%ROOT_DIR%") do set ROOT_DIR=%%~fI
set PACKAGE_SCRIPT=%ROOT_DIR%\cpp\scripts\package_windows.bat
set ISS_SCRIPT=%ROOT_DIR%\cpp\installer\windows\NetworkToolsQt.iss
set DIST_DIR=%ROOT_DIR%\cpp\dist\installers
set ISCC=

if exist "%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe" set ISCC=%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe
if not defined ISCC if exist "%ProgramFiles%\Inno Setup 6\ISCC.exe" set ISCC=%ProgramFiles%\Inno Setup 6\ISCC.exe
if not defined ISCC if exist "%LocalAppData%\Programs\Inno Setup 6\ISCC.exe" set ISCC=%LocalAppData%\Programs\Inno Setup 6\ISCC.exe
if not defined ISCC for /f "delims=" %%I in ('where ISCC.exe 2^>nul') do if not defined ISCC set ISCC=%%I

if not exist "%PACKAGE_SCRIPT%" (
  echo Packaging script not found: %PACKAGE_SCRIPT%
  exit /b 1
)

if not exist "%ISS_SCRIPT%" (
  echo Inno Setup script not found: %ISS_SCRIPT%
  exit /b 1
)

if not defined ISCC (
  echo ISCC.exe not found. Install Inno Setup 6 or run bootstrap_windows_installer.bat
  exit /b 1
)

call "%PACKAGE_SCRIPT%"
if errorlevel 1 exit /b 1

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$exe='%ROOT_DIR%\cpp\dist\NetworkToolsQt\NetworkToolsQt.exe'; $cert=Get-ChildItem Cert:\CurrentUser\My -ErrorAction SilentlyContinue | Where-Object { $_.Subject -eq 'CN=NetworkToolsQt Dev' } | Select-Object -First 1; if ((Test-Path $exe) -and $cert) { Set-AuthenticodeSignature -FilePath $exe -Certificate $cert -TimestampServer 'http://timestamp.digicert.com' | Out-Null }"

if not exist "%DIST_DIR%" mkdir "%DIST_DIR%"
"%ISCC%" "%ISS_SCRIPT%"
if errorlevel 1 exit /b 1

echo Installer created in: %DIST_DIR%\Network-Tools-1.2-Setup-win64.exe
