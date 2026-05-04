# Native Qt/C++ Port Spec

This file is the formal contract for build/runtime/packaging expectations of the native desktop port.

## Goal

Ship a serious desktop release that no longer behaves like a Python prototype:

- native Qt/C++ runtime
- compact dark Russian-first UI
- production-oriented scan workspace
- SSH/Telnet session pages
- transport consoles for Serial/TCP/UDP
- HTTP request page
- SNMP browser
- installer-seeded vendor database
- deployable macOS and Windows outputs
- Linux bootstrap installer flow

## Source of Truth

For version and entry-point questions, trust code first:

- `CMakeLists.txt`
- `src/main.cpp`

Do not assume documentation filenames or installer labels are always fully normalized.

## Required Compile-Time Qt Modules

- `Qt6Core`
- `Qt6Gui`
- `Qt6Widgets`
- `Qt6Network`
- `Qt6Concurrent`
- `Qt6SerialPort`

## Expected Native Runtime Areas

### Core

- `src/core/AppPaths.*`
  runtime paths in app data / application support
- `src/core/SettingsService.*`
  JSON settings, worker count, page state, profiles, quick commands
- `src/core/VendorDbService.*`
  `manuf` seed/load/update/lookup
- `src/core/SnapshotService.*`
  scan baseline save/list/load/diff
- `src/core/TerminalSanitizer.*`
  output sanitization for console-style pages

### Network / runtime

- `src/network/NetworkScanService.*`
- `src/network/HttpRequestService.*`
- `src/network/SerialSession.*`
- `src/network/TcpClientSession.*`
- `src/network/UdpSocketSession.*`
- `src/network/TelnetSession.*`
- `src/network/SshProcessSession.*`

### Widget support

- `src/widgets/CodeEditor.*`

## Scan UI Contract

The scan page is compact and operational, not dashboard-like.

### Controls

Visible top-area behavior should support:

- IP range input
- adapter selection
- auto-IP calculation
- auto-scan timer mode
- prefix mask selection
- start/stop action
- column visibility controls
- sort order toggle

### Table columns

The current runtime table model contains these columns:

- `IP`
- `Ping`
- `MAC`
- `Vendor`
- `Hostname`
- `Web`
- `Gateway`
- `Port`
- `Type`

Some columns may be hidden by default, but they still exist in the model and must stay index-stable unless the UI code is updated carefully.

### Behavioral rules

- only active/detected hosts should remain in the visible grid
- rows can be updated incrementally by later enrichment
- scan comparison mode can mark newly appeared hosts
- on macOS, ARP parsing must normalize both one-digit and two-digit hex octets before vendor lookup

## Vendor / Identity Contract

The `Vendor` field is not a strict manufacturer-only field.

Expected priority:

1. resolved device identity from DNS / Bonjour / cached enrichment
2. manufacturer lookup from `manuf`

This is intentional and must be preserved unless product behavior is explicitly changed.

## External Tool Contract

### SSH

The SSH page is native UI, but the transport still depends on an OS-side SSH client.

macOS/Linux:

- `ssh`
- optionally `sshpass`
- optionally `expect`

Windows:

- `ssh.exe`
- or `plink.exe`

### SNMP

The SNMP browser depends on:

- `snmpwalk`
- `snmpset`
- optional `snmptranslate` for richer OID descriptions

If these tools are missing, the app must show a clear install hint instead of failing silently.

### Scan helpers

Depending on platform, the scan engine may use:

- `ping`
- `arp`
- `netstat`
- `dns-sd`
- `dscacheutil`
- `fping`

The scanner must gracefully fall back to slower native/system paths when optional helpers such as `fping`, `dig`, `host`, or `nslookup` are missing.

## Vendor DB Seeding Contract

The installer or bootstrap path must seed `manuf` before first launch whenever possible.

Primary runtime targets:

- Windows: `%APPDATA%\NetWorkTools\data\manuf`
- macOS: `~/Library/Application Support/NetWorkTools/data/manuf`
- Linux: `~/.local/share/NetWorkTools/data/manuf`

Seeding order:

1. bundled seed inside the packaged app if present
2. download from Wireshark during install/bootstrap if missing
3. only then fall back to runtime recovery by the app

## macOS Packaging Contract

Direct deploy artifact:

- `cpp/dist/Network Tools.app`

Expected packaging behavior:

- `macdeployqt` bundles required Qt frameworks into `Contents/Frameworks`
- bundled resources include vendor DB seed
- bundled resources may include helper binaries such as `fping`
- if optional helpers are not available on the build machine, packaged app must still work through system `ping`/DNS fallbacks
- bundle must include local-network and Bonjour privacy metadata in `Info.plist`

Required bundle privacy keys:

- `NSBonjourServices`
- `NSLocalNetworkUsageDescription`

Why this matters:

- packaged builds on Apple networks may fail to enrich device names correctly without these keys and user approval for local-network access

## Windows Packaging Contract

Expected `windeployqt`-driven runtime contents:

- `Qt6Core.dll`
- `Qt6Gui.dll`
- `Qt6Widgets.dll`
- `Qt6Network.dll`
- `Qt6Concurrent.dll`
- `Qt6SerialPort.dll`
- platform plugin `platforms/qwindows.dll`
- image/style plugins as required by deployment
- compiler runtime via `windeployqt --compiler-runtime`

Installer expectations:

- Inno Setup wizard
- language selection
- target directory selection
- desktop shortcut option
- seeded `%APPDATA%\NetWorkTools\data\manuf`

## Linux Packaging Contract

Current Linux path is a bootstrap installer:

- built on macOS
- copied with source payload
- seeds vendor DB
- installs build dependencies on the Linux target
- builds and installs the native app on the Linux target

It is not currently a prebuilt Linux desktop artifact produced from this macOS workspace.

## Build Commands

Build locally:

```bash
cmake -S cpp -B cpp/build -DCMAKE_BUILD_TYPE=Release
cmake --build cpp/build --config Release
```

Run on macOS/Linux from build output:

```bash
./cpp/build/NetworkToolsQt
```

## Packaging Commands

macOS:

```bash
bash cpp/scripts/package_macos.sh
bash cpp/scripts/build_macos_installer.sh
bash cpp/scripts/install_macos.sh
```

Windows:

```bat
cpp\scripts\package_windows.bat
cpp\scripts\build_windows_installer.bat
cpp\scripts\bootstrap_windows_installer.bat
cpp\scripts\install_windows.bat
```

Linux:

```bash
bash cpp/scripts/build_linux_installer.sh
```

## Known Mismatches To Remember

These are current reality and should not be hidden:

- installer naming in scripts is not fully normalized
- direct macOS bundle naming and installer naming use different conventions
- script and installer version labels are currently normalized to `1.0.6`
- packaging on a clean machine may require additional attention around plugin-driven Qt dependencies

If a future task is about release engineering, inspect the scripts before assuming the docs are perfectly synchronized with every hardcoded name.
