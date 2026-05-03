@echo off
setlocal enabledelayedexpansion

set ROOT_DIR=%~dp0\..\..
set ROOT_DIR=%ROOT_DIR:\/=%
for %%I in ("%ROOT_DIR%") do set ROOT_DIR=%%~fI
set CPP_DIR=%ROOT_DIR%\cpp
set VENV_DIR=%CPP_DIR%\.venv-packaging-win
set QT_ROOT=%CPP_DIR%\tools\Qt
set QT_VERSION=6.11.0
set QT_ARCH=win64_msvc2022_64
set QT_MODULES=qtserialport
set QTDIR=%QT_ROOT%\%QT_VERSION%\msvc2022_64
set BUILD_SCRIPT=%CPP_DIR%\scripts\build_windows_installer.bat

where winget >nul 2>nul
if errorlevel 1 (
  echo winget is required on this machine.
  exit /b 1
)

call :install_package Python.Python.3.12 "Python 3.12"
call :install_package Kitware.CMake "CMake"
call :install_package JRSoftware.InnoSetup "Inno Setup"
call :install_build_tools

where py >nul 2>nul
if errorlevel 1 (
  echo Python launcher py.exe is not available after install.
  exit /b 1
)

if not exist "%VENV_DIR%\Scripts\python.exe" (
  py -3 -m venv "%VENV_DIR%"
  if errorlevel 1 exit /b 1
)

call "%VENV_DIR%\Scripts\activate.bat"
python -m pip install --upgrade pip aqtinstall
if errorlevel 1 exit /b 1

if not exist "%QTDIR%\bin\windeployqt.exe" (
  python -m aqt install-qt -O "%QT_ROOT%" windows desktop %QT_VERSION% %QT_ARCH% -m %QT_MODULES%
  if errorlevel 1 exit /b 1
)

set QTDIR=%QTDIR%
call "%BUILD_SCRIPT%"
exit /b %errorlevel%

:install_package
set PACKAGE_ID=%~1
set PACKAGE_NAME=%~2
echo Installing %PACKAGE_NAME%...
winget install --id %PACKAGE_ID% -e --accept-package-agreements --accept-source-agreements
if errorlevel 1 (
  echo Failed to install %PACKAGE_NAME%.
  exit /b 1
)
exit /b 0

:install_build_tools
echo Installing Visual Studio 2022 Build Tools...
winget install --id Microsoft.VisualStudio.2022.BuildTools -e --accept-package-agreements --accept-source-agreements --override "--quiet --wait --norestart --nocache --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"
if errorlevel 1 (
  echo Failed to install Visual Studio Build Tools.
  exit /b 1
)
exit /b 0
