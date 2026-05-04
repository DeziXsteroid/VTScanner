# C++ / Qt Runtime Notes

## Current runtime

- The native target lives in `cpp/`.
- Shipping runtime:
  - runtime path management;
  - JSON settings;
  - `manuf` vendor DB handling;
  - snapshot storage and diffing;
  - HTTP service;
  - Serial/TCP/UDP native sessions;
  - Telnet session;
  - SSH session wrapper;
  - scan service;
  - serious dark desktop UI direction.

## Release baseline

- no Python runtime in the shipped desktop app;
- single Qt/C++ packaging pipeline;
- seeded vendor DB during install;
- macOS and Windows installers/bootstrap scripts;
- SSH/Telnet profiles persisted in native settings;
- Serial/TCP/UDP quick-command transport panels persisted in native settings.

## Remaining hardening

1. Harden the C++ scan engine and adapter-aware probing against more network edge-cases.
2. Replace the SSH wrapper dependency with bundled `libssh` if a zero-external-client requirement remains mandatory.
3. Verify Windows packaging on a real Windows machine with Qt installed.

## Build

```bash
cmake -S cpp -B cpp/build -DCMAKE_BUILD_TYPE=Release
cmake --build cpp/build --config Release
```

Run:

```bash
./cpp/build/NetworkToolsQt
```

macOS bundle:

```bash
open "/Applications/Network Tools 1.0.8.app"
```

## Packaging scripts

- `cpp/scripts/package_macos.sh`
- `cpp/scripts/build_macos_installer.sh`
- `cpp/scripts/install_macos.sh`
- `cpp/scripts/package_windows.bat`
- `cpp/scripts/build_windows_installer.bat`
- `cpp/scripts/bootstrap_windows_installer.bat`
- `cpp/scripts/install_windows.bat`
- `cpp/scripts/build_linux_installer.sh`

## Spec

See `cpp/PORT_SPEC.md` for:

- required Qt modules;
- expected Windows DLL set;
- installer behavior;
- vendor DB seeding rules;
- launch and packaging commands.
