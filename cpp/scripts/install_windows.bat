@echo off
setlocal enabledelayedexpansion

set ROOT_DIR=%~dp0\..\..
set ROOT_DIR=%ROOT_DIR:\/=%
for %%I in ("%ROOT_DIR%") do set ROOT_DIR=%%~fI
set PACKAGE_DIR=%ROOT_DIR%\cpp\dist\NetworkToolsQt
set TARGET_DIR=%ProgramFiles%\Network Tools 1.0.7
set APPDATA_DIR=%APPDATA%\NetWorkTools
set DATA_DIR=%APPDATA_DIR%\data
set MANUF_PATH=%DATA_DIR%\manuf

if not exist "%PACKAGE_DIR%\NetworkToolsQt.exe" (
  echo Packaged app not found: %PACKAGE_DIR%
  exit /b 1
)

if not exist "%TARGET_DIR%" mkdir "%TARGET_DIR%"
robocopy "%PACKAGE_DIR%" "%TARGET_DIR%" /E /NFL /NDL /NJH /NJS /NC /NS >nul
if errorlevel 8 (
  echo Failed to copy application files.
  exit /b 1
)

if not exist "%DATA_DIR%" mkdir "%DATA_DIR%"
if exist "%PACKAGE_DIR%\data\manuf" (
  copy /Y "%PACKAGE_DIR%\data\manuf" "%MANUF_PATH%" >nul
) else (
  powershell -NoProfile -ExecutionPolicy Bypass -Command ^
    "Invoke-WebRequest -UseBasicParsing -Uri 'https://www.wireshark.org/download/automated/data/manuf' -OutFile '%MANUF_PATH%'"
)

where ssh >nul 2>nul
if errorlevel 1 (
  powershell -NoProfile -ExecutionPolicy Bypass -Command ^
    "try { Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0 | Out-Null } catch { exit 0 }"
)

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$ws = New-Object -ComObject WScript.Shell; " ^
  "$shortcut = $ws.CreateShortcut([System.IO.Path]::Combine([Environment]::GetFolderPath('Desktop'),'Network Tools 1.0.lnk')); " ^
  "$shortcut.TargetPath = '%TARGET_DIR%\NetworkToolsQt.exe'; " ^
  "$shortcut.WorkingDirectory = '%TARGET_DIR%'; " ^
  "$shortcut.Save()"

echo Installed app: %TARGET_DIR%\NetworkToolsQt.exe
echo Vendor DB: %MANUF_PATH%
echo Desktop shortcut created.
