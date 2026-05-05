#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CPP_DIR="$ROOT_DIR/cpp"
BUILD_DIR="$CPP_DIR/build"
DIST_DIR="$CPP_DIR/dist/installers"
PACKAGED_APP="$CPP_DIR/dist/Network Tools.app"
INSTALLER_TEMPLATE="$CPP_DIR/installer/macos/installer.applescript"
INSTALLER_APP="$DIST_DIR/Install Network Tools 1.0.7.app"
DMG_PATH="$DIST_DIR/Network-Tools-1.0.7-macos-installer.dmg"
TMP_DIR="$(mktemp -d)"
STAGE_DIR="$TMP_DIR/stage"
PAYLOAD_DIR="$INSTALLER_APP/Contents/Resources/payload"
PLIST_PATH="$INSTALLER_APP/Contents/Info.plist"
SEED_PATH="$PACKAGED_APP/Contents/Resources/data/manuf"
MANUF_TMP="$TMP_DIR/manuf"
MANUF_URL="https://www.wireshark.org/download/automated/data/manuf"

cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

plist_write() {
  local key="$1"
  local value="$2"
  if /usr/libexec/PlistBuddy -c "Print :$key" "$PLIST_PATH" >/dev/null 2>&1; then
    /usr/libexec/PlistBuddy -c "Set :$key $value" "$PLIST_PATH"
  else
    /usr/libexec/PlistBuddy -c "Add :$key string $value" "$PLIST_PATH"
  fi
}

mkdir -p "$DIST_DIR"

if [[ ! -d "$PACKAGED_APP" ]]; then
  bash "$CPP_DIR/scripts/package_macos.sh"
fi

if [[ ! -d "$PACKAGED_APP" ]]; then
  echo "App bundle not found: $PACKAGED_APP" >&2
  exit 1
fi

if [[ ! -f "$INSTALLER_TEMPLATE" ]]; then
  echo "Installer template not found: $INSTALLER_TEMPLATE" >&2
  exit 1
fi

if [[ -f "$SEED_PATH" ]]; then
  cp "$SEED_PATH" "$MANUF_TMP"
else
  curl -L --fail --silent --show-error "$MANUF_URL" -o "$MANUF_TMP"
fi

rm -rf "$INSTALLER_APP" "$DMG_PATH"
osacompile -o "$INSTALLER_APP" "$INSTALLER_TEMPLATE"
mkdir -p "$PAYLOAD_DIR"
cp -R "$PACKAGED_APP" "$PAYLOAD_DIR/Network Tools 1.0.7.app"
cp "$MANUF_TMP" "$PAYLOAD_DIR/manuf"
cp "$CPP_DIR/resources/app.icns" "$INSTALLER_APP/Contents/Resources/applet.icns"
cp "$CPP_DIR/resources/app.icns" "$INSTALLER_APP/Contents/Resources/droplet.icns"
plist_write "CFBundleIdentifier" "local.networktools.qt.installer"
plist_write "CFBundleName" "Install Network Tools 1.0.7"
plist_write "CFBundleDisplayName" "Install Network Tools 1.0.7"
plist_write "CFBundleIconFile" "applet"
codesign --force --deep --sign - --timestamp=none "$INSTALLER_APP"
codesign --verify --deep --strict --verbose=1 "$INSTALLER_APP"

mkdir -p "$STAGE_DIR"
cp -R "$INSTALLER_APP" "$STAGE_DIR/"
hdiutil create -volname "Network Tools 1.0.7 Installer" -srcfolder "$STAGE_DIR" -ov -format UDZO "$DMG_PATH" >/dev/null

echo "Installer app: $INSTALLER_APP"
echo "DMG: $DMG_PATH"
