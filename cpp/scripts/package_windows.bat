@echo off
setlocal enabledelayedexpansion

set ROOT_DIR=%~dp0\..\..
set ROOT_DIR=%ROOT_DIR:\/=%
for %%I in ("%ROOT_DIR%") do set ROOT_DIR=%%~fI
set CPP_DIR=%ROOT_DIR%\cpp
set BUILD_DIR=%CPP_DIR%\build
set DIST_DIR=%CPP_DIR%\dist\NetworkToolsQt
set EXE_PATH=%BUILD_DIR%\Release\NetworkToolsQt.exe
if not exist "%EXE_PATH%" set EXE_PATH=%BUILD_DIR%\NetworkToolsQt.exe
set QT_PREFIX=
if defined QTDIR set QT_PREFIX=%QTDIR%
if not defined QT_PREFIX if exist "C:\Qt" set QT_PREFIX=C:\Qt
set WINDEPLOYQT=windeployqt
if defined QT_PREFIX if exist "%QT_PREFIX%\bin\windeployqt.exe" set WINDEPLOYQT=%QT_PREFIX%\bin\windeployqt.exe
set CMAKE_QT_ARG=
if defined QT_PREFIX set CMAKE_QT_ARG=-DCMAKE_PREFIX_PATH=%QT_PREFIX%

cmake -S "%CPP_DIR%" -B "%BUILD_DIR%" -G "Visual Studio 17 2022" -A x64 -DCMAKE_BUILD_TYPE=Release %CMAKE_QT_ARG%
if errorlevel 1 exit /b 1

cmake --build "%BUILD_DIR%" --config Release
if errorlevel 1 exit /b 1

if not exist "%EXE_PATH%" (
  echo Built executable not found.
  exit /b 1
)

if not exist "%DIST_DIR%" mkdir "%DIST_DIR%"
copy /Y "%EXE_PATH%" "%DIST_DIR%\NetworkToolsQt.exe" >nul

"%WINDEPLOYQT%" --release --compiler-runtime "%DIST_DIR%\NetworkToolsQt.exe"
if errorlevel 1 (
  echo windeployqt failed.
  exit /b 1
)

if not exist "%DIST_DIR%\data" mkdir "%DIST_DIR%\data"
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "Invoke-WebRequest -UseBasicParsing -Uri 'https://www.wireshark.org/download/automated/data/manuf' -OutFile '%DIST_DIR%\data\manuf'"
if errorlevel 1 (
  echo Failed to download vendor DB seed.
  exit /b 1
)

echo Packaged folder: %DIST_DIR%
echo Next step: run cpp\scripts\install_windows.bat
