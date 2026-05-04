# Network Tools Architecture Map

This document is the quickest way to re-enter the local codebase with real architectural context.

## Product Shape

The application is a native Qt Widgets desktop tool with these user-facing areas:

- IP scanner
- HTTP request page
- Serial page
- TCP page
- UDP page
- SSH page
- Telnet page
- SNMP browser

The UI is compact, desktop-first, dark by default, and optimized around operational workflows rather than abstract component reuse.

## Runtime Object Graph

Startup path:

1. `main.cpp`
   - normalizes `PATH` on GUI launches
   - creates `QApplication`
   - sets app metadata
   - creates runtime folders via `nt::AppPaths`
   - shows `MainWindow`
2. `MainWindow`
   - loads settings
   - instantiates services
   - applies theme/palette/stylesheet
   - builds all pages
   - wires signals and timers
   - can auto-start scan logic

Main long-lived services created by `MainWindow`:

- `nt::SettingsService`
- `nt::VendorDbService`
- `nt::SnapshotService`
- `nt::NetworkScanService`
- `nt::HttpRequestService`
- `nt::SerialSession`
- `nt::SshProcessSession`
- `nt::TcpClientSession`
- `nt::TelnetSession`
- `nt::UdpSocketSession`

## Directory Map

`src/main.cpp`
: App startup and GUI environment preparation.

`src/MainWindow.*`
: Primary orchestration layer for UI, settings, page navigation, scan flow, and transport-page behavior.

`src/core/`
: Persistence and infrastructure services.

`src/network/`
: Scanner, HTTP, and transport/session services.

`src/widgets/`
: Reusable custom widgets. Currently mainly the JSON/code editor.

`resources/`
: Icons, Windows resource file, macOS plist template.

`scripts/`
: Packaging, installer, and deployment helper scripts.

`installer/`
: Installer templates and bootstrap logic.

## Core Data Types

`src/core/Types.h` contains the shared runtime model:

- `AdapterInfo`
- `ScanRecord`
- `RangeSuggestion`
- `SessionProfile`
- `SnapshotMeta`
- `SnapshotDiffEntry`
- `SnapshotDiffSummary`
- `HttpRequestSpec`
- `HttpResponse`

These types are the contract between UI and services.

## MainWindow Responsibilities

`MainWindow` is intentionally broad and currently owns:

- page construction
- menu construction
- theme application
- scan page behavior
- scan table rebuild/filter/column visibility/sort state
- snapshot UI actions
- HTTP request input and history
- Serial/TCP/UDP transport page logic
- SSH/Telnet terminal page logic
- SNMP browser page logic
- persistence glue for quick commands and profiles

Practical implication:

- most UI feature changes go through `MainWindow`
- many regressions happen because a single change touches settings, UI state, and service results together

## Scan Pipeline

The scan flow is the most important runtime path.

### Trigger Path

`MainWindow::startScan()`:

- prevents overlapping launches
- increments `m_currentScanGeneration`
- refreshes auto range when needed
- clears the current table model
- refreshes vendor DB readiness
- starts `NetworkScanService`

### NetworkScanService::start()

The scanner:

1. expands the IP range
2. selects the active adapter
3. caches gateway and mask
4. prefetches ARP table data
5. may pre-warm ARP on on-link targets
6. starts Bonjour enrichment on macOS
7. launches a few prioritized probes early for fast visible results
8. launches a wider concurrent mapping scan over the range

### Probe Logic

`probeHost()` combines several heuristics:

- ping
- retry ping for on-link hosts
- ARP lookup
- basic open-port probing
- reverse-name lookup
- Bonjour/macOS enrichment
- gateway and route labeling
- vendor DB fallback from `manuf`

### Incremental UI Updates

Records can arrive multiple times:

- initial probe result
- later enrichment result
- post-scan RTSP enrichment
- Bonjour name update

The scan table is therefore not a static snapshot built once at the end. It is a live model updated by repeated `recordReady` emissions.

### Vendor Column Semantics

This is easy to misunderstand:

- if a meaningful resolved device identity exists, the `vendor` field may intentionally hold that resolved name
- only when no better resolved identity exists does the code fall back to `VendorDbService::lookupVendor()`

So the `Vendor` column is really closer to:

- resolved device identity first
- manufacturer fallback second

This matters for Apple hardware and Bonjour-heavy networks.

## Name Enrichment Path

macOS device naming relies on several layers:

- ping-resolved names
- reverse lookup
- Bonjour service discovery
- name cache keyed by IP and MAC

Important helpers live inside `NetworkScanService.cpp`, especially around:

- Bonjour browsing
- mDNS resolution
- cached resolved names
- name-vs-vendor fallback

Packaged macOS builds also need bundle privacy keys:

- `NSBonjourServices`
- `NSLocalNetworkUsageDescription`

These are generated from `resources/macos/Info.plist.in`.

## HTTP Page

The HTTP page is straightforward:

- `MainWindow` gathers method, URL, auth, timeout, headers, params, and body
- JSON blocks are edited through `CodeEditor`
- `HttpRequestService` sends via `QNetworkAccessManager`
- response history is stored in settings JSON

Important detail:

- the request page tries to format JSON responses for readability, but it falls back to raw text when parsing fails

## Serial, TCP, and UDP Pages

These transport pages share a similar pattern:

- compact connection controls
- text or HEX payload mode
- optional line ending selection
- quick command slots persisted in settings
- traffic log display

Shared helper logic in `MainWindow`:

- payload parsing
- outgoing display formatting
- line-ending injection
- quick-command persistence

Transport service ownership:

- `SerialSession`
- `TcpClientSession`
- `UdpSocketSession`

## SSH and Telnet Pages

SSH and Telnet use session-style pages with saved profiles.

### Telnet

- native `QTcpSocket`
- primitive prompt detection for login/password auto-send

### SSH

- UI is native C++
- transport still shells out to system SSH tools
- on macOS/Linux can use `ssh`, `sshpass`, or `expect`
- on Windows can use `ssh.exe` or `plink.exe`

### Terminal Rendering

Relevant logic sits in:

- `TerminalSanitizer`
- `MainWindow` terminal draft rendering helpers

The SSH/Telnet terminal path is more advanced than a plain text box:

- sanitized terminal output
- editable draft buffer
- cursor tracking
- event-filter based key handling

## SNMP Browser

The SNMP page is UI-native but process-backed:

- reads use `snmpwalk`
- writes use `snmpset`
- settings persist host, version, communities, v3 auth, and v3 privacy options

This means SNMP functionality depends on OS tooling availability even though the page itself is built in Qt.

## Persistence Model

Runtime paths are controlled by `AppPaths`.

Main persisted artifacts:

- settings JSON
- snapshots JSON files
- vendor DB seed/runtime copy
- log directory scaffold

Settings are centralized in `SettingsService`.

Stored state includes:

- theme and language
- scan worker count
- auto-scan behavior
- window size
- HTTP history
- SSH/Telnet profiles
- SNMP settings
- quick commands for Serial/TCP/UDP
- scan column visibility

## Packaging and Release Structure

Build and release behavior is driven by:

- `CMakeLists.txt`
- `scripts/package_macos.sh`
- `scripts/build_macos_installer.sh`
- `scripts/package_windows.bat`
- `scripts/build_windows_installer.bat`
- `scripts/build_linux_installer.sh`

Important current reality:

- direct macOS deploy artifact is `cpp/dist/Network Tools.app`
- installer naming is currently pinned to `1.0.6` across release scripts
- macOS packaging may require extra attention around `macdeployqt` search paths and plugin-driven Qt frameworks

## High-Risk Editing Zones

These files need extra care:

`src/MainWindow.cpp`
: MainWindow helper namespace and include hub for the focused `src/mainwindow/*.inc` implementation fragments.

`src/mainwindow/*.inc`
: Split MainWindow method bodies. Easy to break page indices, settings keys, or UI assumptions.

`src/network/NetworkScanService.cpp`
: Concurrency, generation-based scan invalidation, OS command usage, enrichment, and vendor/name logic.

`src/core/Types.h`
: Shared contracts. Small changes ripple through UI and services.

`scripts/package_macos.sh`
: Sensitive to local Qt installation layout and plugin/runtime dependency resolution.

## Suggested Reading Order For Future Fixes

If the task is about scan results:

1. `src/core/Types.h`
2. `src/MainWindow.cpp`
3. `src/mainwindow/MainWindowScan.inc`
4. `src/network/NetworkScanService.cpp`
5. `src/core/VendorDbService.cpp`

If the task is about sessions or terminals:

1. `src/MainWindow.cpp`
2. `src/mainwindow/MainWindowTransports.inc`
3. `src/core/TerminalSanitizer.cpp`
4. the relevant session implementation in `src/network/`

If the task is about packaging:

1. `cpp/CMakeLists.txt`
2. `resources/macos/Info.plist.in`
3. `scripts/package_macos.sh`
4. `scripts/build_macos_installer.sh`
5. `cpp/PORT_SPEC.md`

## Known Constraints and TODO Pressure

- `MainWindow` is a real refactor candidate, but right now it is also the project knowledge hub
- SSH is still external-client based
- SNMP is still external-tool based
- packaging version naming is partially inconsistent
- Windows packaging is less battle-tested than local macOS packaging
- macOS Apple-name enrichment depends on both runtime logic and OS privacy permission flow
