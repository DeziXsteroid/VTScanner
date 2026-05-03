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

if not exist "%DIST_DIR%" mkdir "%DIST_DIR%"
"%ISCC%" "%ISS_SCRIPT%"
if errorlevel 1 exit /b 1

echo Installer created in: %DIST_DIR%\Network-Tools-1.0-Setup-win64.exe
