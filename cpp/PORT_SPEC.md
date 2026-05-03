# Native Qt/C++ Port Spec

## Goal

Ship a serious desktop release that no longer looks or behaves like a Python prototype:

- native Qt/C++ runtime;
- compact dark Russian UI;
- production-first scan workspace;
- SSH/Telnet profiles;
- installer-seeded vendor database;
- deployable macOS and Windows builds.

## Required runtime modules

Qt modules:

- `Qt6Core`
- `Qt6Gui`
- `Qt6Widgets`
- `Qt6Network`
- `Qt6Concurrent`
- `Qt6SerialPort`

Windows runtime files expected from `windeployqt`:

- `Qt6Core.dll`
- `Qt6Gui.dll`
- `Qt6Widgets.dll`
- `Qt6Network.dll`
- `Qt6Concurrent.dll`
- `Qt6SerialPort.dll`
- platform plugin `platforms/qwindows.dll`
- style/image plugins required by Qt deployment
- compiler runtime from `windeployqt --compiler-runtime`

macOS runtime:

- bundled `.app` with `macdeployqt`
- Qt frameworks copied inside `Contents/Frameworks`
- vendor seed placed into `Contents/MacOS/data/manuf`

## Native service map

- `src/core/AppPaths.*`
  runtime paths in AppData/Application Support.
- `src/core/SettingsService.*`
  JSON settings, window state, workers, session profiles.
- `src/core/VendorDbService.*`
  `manuf` seed/load/update/lookup.
- `src/core/SnapshotService.*`
  save/list/load/diff baseline snapshots.
- `src/core/TerminalSanitizer.*`
  preserves terminal control sequences required for SSH/Telnet rendering while filtering unsafe noise.
- `src/network/NetworkScanService.*`
  adapters, auto range, host probing, MAC/vendor enrichment, route and open-port summary.
- `src/network/HttpRequestService.*`
  native HTTP requests.
- `src/network/TelnetSession.*`
  native Telnet session over `QTcpSocket`.
- `src/network/SshProcessSession.*`
  native C++ wrapper around system SSH client with sanitized terminal output.

## Installer behavior

The installer must seed `manuf` before first launch.

Primary target path:

- Windows: `%APPDATA%\NetWorkTools\data\manuf`
- macOS: `~/Library/Application Support/NetWorkTools/data/manuf`

Seeding order:

1. copy bundled `data/manuf` from packaged app if present;
2. if missing, download from Wireshark `manuf` URL during install/bootstrap;
3. only if both fail, let the app try runtime recovery from Settings.

## Scan UI contract

- Top controls must stay compact and fixed-width instead of stretching across wide monitors.
- Visible controls: `Диапазон IP`, `Адаптер`, `Авто IP`, `Маска`, `Старт`.
- Table columns: `IP`, `Пинг`, `MAC`, `Вендор`, `Маршрут`, `Порт`.
- Only active or detected hosts should be inserted into the grid.
- On macOS, ARP parsing must normalize both one-digit and two-digit hex octets before vendor lookup.

## SSH strategy

Current native runtime uses a compiled C++ wrapper, but the SSH transport still depends on an SSH client on the target OS:

- macOS/Linux: `ssh`, optionally `sshpass` for password injection;
- Windows: `ssh.exe` or `plink.exe`.

Windows installer note:

- `cpp/scripts/install_windows.bat` performs a best-effort install of the Windows OpenSSH client if `ssh.exe` is missing.

If zero external SSH client dependency is required, the next hardening step is replacing this wrapper with bundled `libssh` or `libssh2`.

## Installer outputs

Windows:

- Inno Setup wizard
- language selection page
- target directory page
- desktop shortcut task
- seeded `%APPDATA%\NetWorkTools\data\manuf`

macOS:

- DMG containing `Install Network Tools 1.0.app`
- installed app path `/Applications/Network Tools 1.0.app`
- interactive installer prompts for language, destination folder and desktop shortcut
- seeded `~/Library/Application Support/NetWorkTools/data/manuf`

Linux:

- bootstrap `.run` installer built from macOS
- prompts for language, destination folder and desktop shortcut
- installs Linux build dependencies on target host
- builds and installs native binary on target Linux host

## Launch commands

Build locally:

```bash
cmake -S cpp -B cpp/build -DCMAKE_BUILD_TYPE=Release
cmake --build cpp/build --config Release
```

Run on macOS/Linux from build output:

```bash
./cpp/build/NetworkToolsQt
```

If CMake generates an app bundle on macOS, run:

```bash
open "/Applications/Network Tools 1.0.app"
```

## Packaging commands

macOS:

```bash
bash cpp/scripts/package_macos.sh
bash cpp/scripts/build_macos_installer.sh
```

Windows:

```bat
cpp\scripts\package_windows.bat
cpp\scripts\build_windows_installer.bat
cpp\scripts\bootstrap_windows_installer.bat
```

Linux:

```bash
bash cpp/scripts/build_linux_installer.sh
```
