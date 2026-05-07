@echo off
setlocal enabledelayedexpansion

set ROOT_DIR=%~dp0\..\..
set ROOT_DIR=%ROOT_DIR:\/=%
for %%I in ("%ROOT_DIR%") do set ROOT_DIR=%%~fI
set CPP_DIR=%ROOT_DIR%\cpp
set BUILD_DIR=%CPP_DIR%\build-windows
set DIST_DIR=%CPP_DIR%\dist\NetworkToolsQt
set MANUF_URL=https://www.wireshark.org/download/automated/data/manuf

set QT_PREFIX=
if defined QTDIR if exist "%QTDIR%\bin\qmake.exe" set QT_PREFIX=%QTDIR%
if not defined QT_PREFIX (
  for /d %%V in ("C:\Qt\*") do (
    if not defined QT_PREFIX if exist "%%~fV\mingw_64\bin\qmake.exe" set QT_PREFIX=%%~fV\mingw_64
  )
)
if not defined QT_PREFIX (
  for /d %%V in ("C:\Qt\*") do (
    if not defined QT_PREFIX if exist "%%~fV\msvc2022_64\bin\qmake.exe" set QT_PREFIX=%%~fV\msvc2022_64
  )
)
if not defined QT_PREFIX (
  echo Qt 6 was not found. Set QTDIR to a Qt kit root, for example C:\Qt\6.8.2\mingw_64.
  exit /b 1
)

set WINDEPLOYQT=%QT_PREFIX%\bin\windeployqt.exe
if not exist "%WINDEPLOYQT%" (
  echo windeployqt not found: %WINDEPLOYQT%
  exit /b 1
)

set GENERATOR=Visual Studio 17 2022
set GENERATOR_ARGS=-A x64
set BUILD_CONFIG=--config Release
set EXE_PATH=%BUILD_DIR%\Release\NetworkToolsQt.exe

echo !QT_PREFIX! | findstr /I "\\mingw_" >nul
if not errorlevel 1 (
  set MINGW_BIN=
  for /d %%M in ("C:\Qt\Tools\mingw*_64") do (
    if not defined MINGW_BIN if exist "%%~fM\bin\g++.exe" set MINGW_BIN=%%~fM\bin
  )
  if not defined MINGW_BIN (
    for /f "delims=" %%G in ('where g++.exe 2^>nul') do if not defined MINGW_BIN for %%P in ("%%G\..") do set MINGW_BIN=%%~fP
  )
  if not defined MINGW_BIN (
    echo MinGW compiler was not found for Qt kit: !QT_PREFIX!
    exit /b 1
  )
  set PATH=!MINGW_BIN!;!QT_PREFIX!\bin;!PATH!
  set GENERATOR=MinGW Makefiles
  set GENERATOR_ARGS=
  set BUILD_CONFIG=
  set EXE_PATH=%BUILD_DIR%\NetworkToolsQt.exe
) else (
  set PATH=!QT_PREFIX!\bin;!PATH!
)

echo Using Qt: %QT_PREFIX%
echo Using CMake generator: %GENERATOR%

cmake -S "%CPP_DIR%" -B "%BUILD_DIR%" -G "%GENERATOR%" %GENERATOR_ARGS% -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH="%QT_PREFIX%"
if errorlevel 1 exit /b 1

cmake --build "%BUILD_DIR%" %BUILD_CONFIG% -j 4
if errorlevel 1 exit /b 1

if not exist "%EXE_PATH%" (
  echo Built executable not found: %EXE_PATH%
  exit /b 1
)

if exist "%DIST_DIR%" rmdir /S /Q "%DIST_DIR%"
mkdir "%DIST_DIR%"
copy /Y "%EXE_PATH%" "%DIST_DIR%\NetworkToolsQt.exe" >nul

"%WINDEPLOYQT%" --release --compiler-runtime "%DIST_DIR%\NetworkToolsQt.exe"
if errorlevel 1 (
  echo windeployqt failed.
  exit /b 1
)

if not exist "%DIST_DIR%\data" mkdir "%DIST_DIR%\data"
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$ProgressPreference='SilentlyContinue'; Invoke-WebRequest -UseBasicParsing -Uri '%MANUF_URL%' -OutFile '%DIST_DIR%\data\manuf'"
if errorlevel 1 (
  echo Failed to download vendor DB seed.
  exit /b 1
)

set NETSNMP_ROOT=
if exist "C:\Net-SNMP\bin\snmpwalk.exe" set NETSNMP_ROOT=C:\Net-SNMP
if not defined NETSNMP_ROOT if exist "C:\Program Files\Net-SNMP\bin\snmpwalk.exe" set NETSNMP_ROOT=C:\Program Files\Net-SNMP
if not defined NETSNMP_ROOT if exist "C:\Program Files (x86)\Net-SNMP\bin\snmpwalk.exe" set NETSNMP_ROOT=C:\Program Files (x86)\Net-SNMP

if defined NETSNMP_ROOT (
  echo Bundling Net-SNMP from: !NETSNMP_ROOT!
  if not exist "%DIST_DIR%\bin" mkdir "%DIST_DIR%\bin"
  for %%T in (snmpwalk snmpget snmpset snmptranslate) do (
    if exist "!NETSNMP_ROOT!\bin\%%T.exe" copy /Y "!NETSNMP_ROOT!\bin\%%T.exe" "%DIST_DIR%\bin\" >nul
  )
  copy /Y "!NETSNMP_ROOT!\bin\*.dll" "%DIST_DIR%\bin\" >nul 2>nul
  if exist "!NETSNMP_ROOT!\share\snmp\mibs" (
    robocopy "!NETSNMP_ROOT!\share\snmp\mibs" "%DIST_DIR%\share\snmp\mibs" /E /NFL /NDL /NJH /NJS /NP >nul
    if errorlevel 8 exit /b 1
  )
  if exist "!NETSNMP_ROOT!\etc\snmp" (
    robocopy "!NETSNMP_ROOT!\etc\snmp" "%DIST_DIR%\etc\snmp" /E /NFL /NDL /NJH /NJS /NP >nul
    if errorlevel 8 exit /b 1
  )
) else (
  echo Warning: Net-SNMP was not found, SNMP tools will not be bundled.
)

echo Packaged folder: %DIST_DIR%
echo Executable: %DIST_DIR%\NetworkToolsQt.exe
