# Network Tools Developer Overview

This repository contains the native Qt/C++ desktop version of Network Tools. The practical goal of this local documentation set is to let a new chat or a new contributor enter the codebase quickly without reverse-engineering `MainWindow.cpp` from scratch.

## Start Here

Read the documents in this order:

1. `cpp/ARCHITECTURE.md`
   Complete architecture map, runtime object graph, scan pipeline, transport pages, persistence, and risky edit zones.
2. `CPP_MIGRATION.md`
   Native runtime notes, maintenance constraints, platform dependencies, and what is already shipped versus what is still fragile.
3. `cpp/PORT_SPEC.md`
   Build, runtime, installer, and release contract for macOS, Windows, and Linux bootstrap packaging.

## Fast Project Snapshot

- Main native source tree: `cpp/`
- Build system: `CMake`
- Language level: `C++20`
- UI stack: `Qt Widgets`
- Main entry point: `cpp/src/main.cpp`
- Main orchestration layer: `cpp/src/MainWindow.cpp`
- Core service folders:
  - `cpp/src/core/`
  - `cpp/src/network/`
  - `cpp/src/widgets/`

Main feature surfaces in the desktop app:

- IP scanner
- HTTP request console
- Serial transport console
- TCP transport console
- UDP transport console
- SSH session page
- Telnet session page
- SNMP browser

## Current Architectural Reality

The project is service-oriented, but not heavily layered:

- `MainWindow` owns almost all UI wiring and a large amount of flow logic.
- Runtime services handle the actual mechanics:
  - settings
  - vendor DB
  - snapshots
  - scan engine
  - HTTP requests
  - Serial/TCP/UDP sessions
  - SSH/Telnet sessions
- Persistent state is JSON-based and stored under app data directories managed by `AppPaths`.
- The scan table is incremental and event-driven: records arrive during the scan, and post-enrichment can update the same rows later.

This means most feature work touches two layers at once:

- UI state and persistence in `MainWindow`
- the actual runtime behavior in one of the services

## Build and Run

Local native build:

```bash
cmake -S cpp -B cpp/build -DCMAKE_BUILD_TYPE=Release
cmake --build cpp/build --config Release
```

Run from the build output:

```bash
./cpp/build/NetworkToolsQt
```

macOS direct package:

```bash
bash cpp/scripts/package_macos.sh
```

macOS local install:

```bash
bash cpp/scripts/install_macos.sh
```

## Non-Obvious Facts Worth Knowing Early

- The `Vendor` column is not a pure manufacturer column. If the scanner resolves a better device identity from DNS, Bonjour, or related name enrichment, that resolved device name can intentionally replace the raw manufacturer label.
- Apple device naming in packaged macOS builds depends on both:
  - Bonjour/local-network runtime behavior in `NetworkScanService`
  - privacy keys in the app bundle `Info.plist`
- The SSH page is native C++ UI, but the transport still depends on an external SSH client on the target system.
- The SNMP page is also native UI, but it shells out to system `snmpwalk` and `snmpset`.
- `MainWindow` is still the main orchestration class, but its method bodies are split under `cpp/src/mainwindow/`. Be careful with changes that affect:
  - page indices
  - saved settings keys
  - scan column indices
  - signal/slot wiring

## Current Documentation Intent

These Markdown files are optimized for local onboarding and future maintenance, not for public release marketing. They should describe the codebase as it actually behaves, including:

- current architecture
- runtime ownership
- persistence model
- packaging assumptions
- known mismatches and release risks

## Useful File Entry Points

- `cpp/src/main.cpp`
- `cpp/src/MainWindow.h`
- `cpp/src/MainWindow.cpp`
- `cpp/src/mainwindow/*.inc`
- `cpp/src/core/Types.h`
- `cpp/src/core/SettingsService.*`
- `cpp/src/core/VendorDbService.*`
- `cpp/src/core/SnapshotService.*`
- `cpp/src/network/NetworkScanService.*`
- `cpp/src/network/HttpRequestService.*`
- `cpp/src/network/SshProcessSession.*`
- `cpp/src/network/TelnetSession.*`
- `cpp/src/network/SerialSession.*`
- `cpp/src/network/TcpClientSession.*`
- `cpp/src/network/UdpSocketSession.*`
- `cpp/src/widgets/CodeEditor.*`

## Known Documentation Caveat

Version naming is not perfectly normalized across all packaging scripts in the current workspace. The authoritative source version should be treated as whatever is currently set in:

- `cpp/CMakeLists.txt`
- `cpp/src/main.cpp`

If a future task is about release naming, installer naming, or asset naming, inspect the scripts before trusting a document blindly.
