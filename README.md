# Network Tools 1.0.5

Native Qt/C++ network utility with a production desktop runtime, compact scan workspace, transport consoles and installer-seeded vendor database.

## Primary target

- Native app source: `cpp/`
- Build system: `CMake`
- UI stack: `Qt Widgets`
- Default visual direction:
  - dark theme;
  - Russian UI;
  - compact desktop window;
  - pressed button feedback;
  - no helper clutter in the scan workspace.

## Core runtime

- Runtime paths and settings storage.
- Vendor `manuf` DB seed/load/update logic.
- Snapshot save/list/load/diff service.
- HTTP request service.
- Serial native session.
- TCP native session.
- UDP native session.
- Telnet native session.
- SSH native C++ wrapper around system SSH client.
- terminal rendering path for SSH/Telnet with editable input, draft buffer and ANSI-aware output.
- Native scan service with adapter discovery, auto range and host probing.
- Hercules-style Serial/TCP/UDP transport logs with saved quick commands.

## Current scan workspace

- Top bar uses `Диапазон IP`, `Адаптер`, `Авто IP`, `Авто скан`, `Маска` and `Старт`.
- `Авто IP` recalculates the range from the selected adapter and prefix mask.
- `Авто скан` can restart the scan automatically by timer without pressing `Старт`.
- The grid only keeps detected hosts, not every IP from the raw range.
- Scan columns are currently: `IP`, `Пинг`, `MAC`, `Вендор`, `Шлюз IP`, `Откр. порт`.
- On macOS, MAC parsing accepts single-digit ARP octets, so vendor lookup works for entries like `30:24:a9:13:7f:d`.

## Native build

```bash
cmake -S cpp -B cpp/build -DCMAKE_BUILD_TYPE=Release
cmake --build cpp/build --config Release
```

Run from build output:

```bash
./cpp/build/NetworkToolsQt
```

On macOS, if a bundle is produced:

```bash
open "/Applications/Network Tools 1.0.5.app"
```

## Installers and packaging

macOS installer build on this machine:

```bash
bash cpp/scripts/build_macos_installer.sh
open "cpp/dist/installers/Network-Tools-1.0.5-macos-installer.dmg"
```

macOS direct package and local install:

```bash
bash cpp/scripts/package_macos.sh
bash cpp/scripts/install_macos.sh
```

Windows installer build on a prepared Windows machine:

```bat
cpp\scripts\build_windows_installer.bat
```

Windows bootstrap build on a clean Windows machine:

```bat
cpp\scripts\bootstrap_windows_installer.bat
```

Linux bootstrap installer build from this macOS workspace:

```bash
bash cpp/scripts/build_linux_installer.sh
```

Linux bootstrap run on a Linux target:

```bash
chmod +x Network-Tools-1.0.5-linux-bootstrap.run
./Network-Tools-1.0.5-linux-bootstrap.run
```

Installer artifacts currently produced by the project:

- macOS installer app: `cpp/dist/installers/Install Network Tools 1.0.5.app`
- macOS installer DMG: `cpp/dist/installers/Network-Tools-1.0.5-macos-installer.dmg`
- Linux bootstrap installer: `cpp/dist/installers/Network-Tools-1.0.5-linux-bootstrap.run`
- macOS deploy bundle: `cpp/dist/Network Tools.app`
- macOS deploy zip: `cpp/dist/Network-Tools-macos.zip`

Windows output after a successful Windows build:

- staging folder: `cpp\dist\NetworkToolsQt`
- final setup: `cpp\dist\installers\Network-Tools-1.0.5-Setup-win64.exe`

## Vendor DB behavior

The installer/bootstrap scripts seed `manuf` before first launch.

Runtime locations:

- macOS: `~/Library/Application Support/NetWorkTools/data/manuf`
- Windows: `%APPDATA%/NetWorkTools/data/manuf`
- Linux: `~/.local/share/NetWorkTools/data/manuf`

If the seeded file is missing, the C++ runtime can still recover it from the Wireshark source.

Manual refresh command used during local maintenance:

```bash
curl -L --fail --silent --show-error https://www.wireshark.org/download/automated/data/manuf -o "$HOME/Library/Application Support/NetWorkTools/data/manuf"
```

## Transport notes

- `Serial`, `TCP` and `UDP` accept text or raw HEX payloads.
- The `HEX` toggle affects both outgoing payload display and incoming payload rendering.
- TCP and UDP can be used for binary control protocols, including VISCA-style HEX frames, as long as the target side expects raw byte streams/datagrams.

## Packaging notes

- Windows setup uses Inno Setup, so the installer shows language selection, install path and desktop shortcut selection.
- macOS setup is a native installer app packed into a DMG. It asks for language, destination folder and desktop shortcut creation, then seeds `manuf` into Application Support.
- Linux output is a bootstrap installer, not a prebuilt native Linux binary from this macOS host. The `.run` artifact prompts for language, install path and desktop shortcut, installs Qt build dependencies on the Linux target, builds the app there and then installs it.

## References

- `CPP_MIGRATION.md`
- `cpp/PORT_SPEC.md`
- `cpp/CMakeLists.txt`
- `cpp/src/MainWindow.cpp`
- `cpp/src/core/`
- `cpp/src/network/`
