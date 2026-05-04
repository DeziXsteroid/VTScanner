# C++ / Qt Runtime Notes

This file is the maintenance note set for the native desktop runtime. It is not a marketing README and not a formal release spec. Its job is to explain what is actually native today, what still depends on external tools, and where future hardening work is likely to land.

## What Exists Today

The native target lives in `cpp/` and already ships a substantial C++/Qt desktop runtime:

- runtime path management
- JSON settings persistence
- vendor `manuf` DB seed/load/lookup behavior
- snapshot storage and diffing
- HTTP request service
- native Serial/TCP/UDP transport pages
- native Telnet page
- native SSH page backed by an external SSH client
- native scan service with adapter discovery and multi-step host probing
- dark compact desktop UI with Russian-first labels and optional English UI mode

## What Is Truly Native

Already implemented inside the desktop app:

- Qt Widgets UI
- scan page
- HTTP page
- Serial/TCP/UDP transport pages
- SSH/Telnet session pages
- SNMP browser page
- settings and profile persistence
- snapshot compare workflow
- vendor DB runtime loading

Still dependent on external OS tools even though the UI is native:

- SSH transport
- SNMP read/write commands
- several network scan helper commands on macOS/Linux

The runtime should treat optional helper tools as accelerators, not hard requirements. If `fping` or DNS helper tools are missing, scanning should continue with slower fallbacks; if SNMP tools are missing, the UI should show a direct install hint.

## Important Runtime Characteristics

### 1. MainWindow is the orchestration center

The code is service-based, but not strongly separated into presentation and application layers. The `MainWindow` implementation is split between `MainWindow.cpp` and focused `src/mainwindow/*.inc` fragments, and that orchestration layer is where:

- most page widgets are built
- settings are read and written
- service signals are translated into UI updates
- scan results are rendered and re-rendered
- transport quick commands are persisted
- session profiles are managed

This is not necessarily elegant, but it is the current architectural truth.

### 2. The scan pipeline is incremental

The scan page does not wait for a single monolithic result set. It receives:

- early results
- normal probe results
- Bonjour updates
- RTSP-related post-enrichment

So the same row can improve over time.

### 3. The vendor column is identity-first, manufacturer-second

If the scanner resolves a more meaningful device name, especially through DNS or Bonjour on Apple-heavy networks, that resolved identity can replace the plain manufacturer label.

Fallback order is effectively:

1. resolved identity
2. cached name
3. vendor DB lookup from `manuf`

### 4. Runtime persistence is JSON-oriented

Settings, profiles, quick commands, and several UI behaviors are persisted through JSON rather than platform-native registry/plist abstractions.

## Service Map

Core services:

- `src/core/AppPaths.*`
- `src/core/SettingsService.*`
- `src/core/VendorDbService.*`
- `src/core/SnapshotService.*`
- `src/core/TerminalSanitizer.*`

Network/runtime services:

- `src/network/NetworkScanService.*`
- `src/network/HttpRequestService.*`
- `src/network/SerialSession.*`
- `src/network/TcpClientSession.*`
- `src/network/UdpSocketSession.*`
- `src/network/TelnetSession.*`
- `src/network/SshProcessSession.*`

Widget support:

- `src/widgets/CodeEditor.*`

## Platform Dependencies That Matter

### macOS

Expected helper commands in practice:

- `ping`
- `arp`
- `netstat`
- `dns-sd`
- `dscacheutil`
- `ssh`
- optionally `sshpass`
- optionally `expect`
- optionally `fping`

Apple-name enrichment in packaged builds also depends on:

- correct bundle privacy keys in `Info.plist`
- user approval for local network access when macOS prompts

### Windows

Expected packaging helpers:

- Visual Studio Build Tools
- Qt with `windeployqt`
- Inno Setup

Expected runtime helper tools:

- `ssh.exe` or `plink.exe`
- optional OpenSSH client install through the helper script

### Linux

The current Linux deliverable is a bootstrap installer, not a prebuilt binary from this macOS workspace.

## Packaging Reality

There is one Qt/C++ packaging pipeline, but the scripts are not perfectly normalized:

- source version values are defined in `cpp/CMakeLists.txt` and `cpp/src/main.cpp`
- some installer paths and labels still use legacy naming
- macOS direct deploy and installer paths are not always expressed with the same naming style

That inconsistency is documentation-worthy because future chats are likely to hit it when asked to fix releases.

## Known Hardening Backlog

1. Harden the scan engine and adapter-aware probing across more edge cases.
2. Replace the SSH wrapper dependency with bundled `libssh` or similar if zero external SSH dependency becomes mandatory.
3. Make release naming consistent across:
   - CMake version
   - app version
   - installer naming
   - README instructions
   - release asset naming
4. Re-check macOS packaging on a clean machine for plugin-driven `macdeployqt` surprises.
5. Verify Windows packaging on a real Windows machine with the intended Qt layout.

## Practical Reading Guide

If a future chat asks about architecture, start with:

- `README.md`
- `cpp/ARCHITECTURE.md`
- `cpp/PORT_SPEC.md`

If it asks about scan behavior:

- `src/MainWindow.cpp`
- `src/mainwindow/*.inc`
- `src/network/NetworkScanService.cpp`
- `src/core/VendorDbService.cpp`

If it asks about release/build behavior:

- `cpp/CMakeLists.txt`
- `cpp/resources/macos/Info.plist.in`
- `cpp/scripts/`
- `cpp/PORT_SPEC.md`
