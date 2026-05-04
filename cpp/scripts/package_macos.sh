#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CPP_DIR="$ROOT_DIR/cpp"
BUILD_DIR="$CPP_DIR/build"
DIST_DIR="$CPP_DIR/dist"
DISPLAY_NAME="Network Tools"
APP_BUNDLE_NAME="$DISPLAY_NAME.app"
ZIP_BASENAME="Network-Tools-macos"
DMG_BASENAME="Network-Tools-macos-apple-silicon"
DMG_VOLUME_NAME="Install Network Tools"
DMG_WINDOW_LEFT=140
DMG_WINDOW_TOP=120
DMG_WINDOW_WIDTH=720
DMG_WINDOW_HEIGHT=420
DMG_APP_POS_X=180
DMG_APP_POS_Y=230
DMG_APPS_POS_X=520
DMG_APPS_POS_Y=230

APP_ICON_SOURCE="$CPP_DIR/resources/app.icns"

BREW_PREFIX="$(brew --prefix)"
QT_PREFIX="$(brew --prefix qt)"
BUILD_APP_PATH=""
APP_PATH="$DIST_DIR/$APP_BUNDLE_NAME"
RESOURCES_DIR="$APP_PATH/Contents/Resources"
FRAMEWORKS_DIR="$APP_PATH/Contents/Frameworks"
SEED_DIR="$RESOURCES_DIR/data"
SEED_PATH="$SEED_DIR/manuf"
BIN_DIR="$RESOURCES_DIR/bin"
MANUF_URL="https://www.wireshark.org/download/automated/data/manuf"
FPING_SOURCE="${NETWORKTOOLS_FPING_SOURCE:-}"

TEMP_DMG=""
MOUNT_DEVICE=""
MOUNT_POINT=""
STAGE_DIR=""

cleanup() {
  if [[ -n "$MOUNT_DEVICE" ]]; then
    hdiutil detach "$MOUNT_DEVICE" -force >/dev/null 2>&1 || true
  fi
  if [[ -n "$TEMP_DMG" ]]; then
    rm -f "$TEMP_DMG"
  fi
  if [[ -n "$STAGE_DIR" ]]; then
    rm -rf "$STAGE_DIR"
  fi
}
trap cleanup EXIT

find_build_app() {
  if [[ ! -d "$BUILD_DIR" ]]; then
    return 0
  fi
  if [[ -d "$BUILD_DIR/NetworkToolsQt.app" ]]; then
    printf '%s\n' "$BUILD_DIR/NetworkToolsQt.app"
    return
  fi
  find "$BUILD_DIR" -maxdepth 1 -type d -name '*.app' | head -n 1
}

copy_optional_dependency() {
  local src="$1"
  local dst_dir="$2"
  local dst_name="${3:-$(basename "$src")}"
  if [[ -f "$src" ]]; then
    cp -f "$src" "$dst_dir/$dst_name"
    install_name_tool -id "@executable_path/../Frameworks/$dst_name" "$dst_dir/$dst_name" >/dev/null 2>&1 || true
  fi
}

bundle_extra_runtime_deps() {
  mkdir -p "$FRAMEWORKS_DIR"
  copy_optional_dependency "$BREW_PREFIX/lib/libgraphite2.3.dylib" "$FRAMEWORKS_DIR"
  copy_optional_dependency "$BREW_PREFIX/lib/libdbus-1.3.dylib" "$FRAMEWORKS_DIR"
}

find_optional_tool() {
  local name="$1"
  local configured="${2:-}"
  if [[ -n "$configured" && -x "$configured" ]]; then
    printf '%s\n' "$configured"
    return
  fi
  if command -v "$name" >/dev/null 2>&1; then
    command -v "$name"
    return
  fi
  for candidate in "/usr/bin/$name" "/usr/local/bin/$name" "$BREW_PREFIX/bin/$name"; do
    if [[ -x "$candidate" ]]; then
      printf '%s\n' "$candidate"
      return
    fi
  done
}

configure_dmg_finder_window() {
  local volume_name="$1"
  local right=$((DMG_WINDOW_LEFT + DMG_WINDOW_WIDTH))
  local bottom=$((DMG_WINDOW_TOP + DMG_WINDOW_HEIGHT))

  osascript <<OSA
tell application "Finder"
    tell disk "${volume_name}"
        open
        tell container window
            set current view to icon view
            set toolbar visible to false
            set statusbar visible to false
            set bounds to {${DMG_WINDOW_LEFT}, ${DMG_WINDOW_TOP}, ${right}, ${bottom}}
        end tell
        set position of item "${APP_BUNDLE_NAME}" of container window to {${DMG_APP_POS_X}, ${DMG_APP_POS_Y}}
        set position of item "Applications" of container window to {${DMG_APPS_POS_X}, ${DMG_APPS_POS_Y}}
        update without registering applications
        delay 1
        close
        open
    end tell
end tell
OSA
}

create_pretty_dmg() {
  local dmg_path="$1"
  STAGE_DIR="$(mktemp -d /tmp/networktools-dmg-stage.XXXXXX)"

  cp -R "$APP_PATH" "$STAGE_DIR/$APP_BUNDLE_NAME"
  ln -s /Applications "$STAGE_DIR/Applications"
  cp -f "$APP_ICON_SOURCE" "$STAGE_DIR/.VolumeIcon.icns"

  TEMP_DMG="$DIST_DIR/${DMG_BASENAME}-tmp.dmg"
  rm -f "$TEMP_DMG" "$dmg_path"
  hdiutil create \
    -volname "$DMG_VOLUME_NAME" \
    -srcfolder "$STAGE_DIR" \
    -fs HFS+ \
    -format UDRW \
    "$TEMP_DMG" >/dev/null

  local attach_output
  attach_output="$(hdiutil attach -readwrite -noverify -noautoopen "$TEMP_DMG")"
  MOUNT_DEVICE="$(printf '%s\n' "$attach_output" | awk '/Apple_HFS/ {print $1; exit}')"
  MOUNT_POINT="$(printf '%s\n' "$attach_output" | awk '/Apple_HFS/ {print $NF; exit}')"
  if [[ -z "$MOUNT_DEVICE" || -z "$MOUNT_POINT" ]]; then
    echo "Failed to attach temporary DMG." >&2
    exit 1
  fi

  SetFile -a V "$MOUNT_POINT/.VolumeIcon.icns" >/dev/null 2>&1 || true
  SetFile -a C "$MOUNT_POINT" >/dev/null 2>&1 || true

  configure_dmg_finder_window "$DMG_VOLUME_NAME"

  sync
  hdiutil detach "$MOUNT_DEVICE" -force >/dev/null
  MOUNT_DEVICE=""
  MOUNT_POINT=""

  hdiutil convert "$TEMP_DMG" -format UDZO -imagekey zlib-level=9 -o "$dmg_path" >/dev/null
}

mkdir -p "$DIST_DIR"

cmake -S "$CPP_DIR" -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=Release
cmake --build "$BUILD_DIR" --config Release
BUILD_APP_PATH="$(find_build_app)"

if [[ -z "$BUILD_APP_PATH" || ! -d "$BUILD_APP_PATH" ]]; then
  echo "Expected build app bundle not found in: $BUILD_DIR" >&2
  exit 1
fi

if ! command -v macdeployqt >/dev/null 2>&1; then
  echo "macdeployqt is required and was not found in PATH." >&2
  exit 1
fi

rm -rf "$APP_PATH"
cp -R "$BUILD_APP_PATH" "$APP_PATH"

MACDEPLOYQT_ARGS=(
  -always-overwrite
  "-libpath=$BREW_PREFIX/lib"
  "-libpath=$BREW_PREFIX/Frameworks"
  "-libpath=$QT_PREFIX/lib"
)
if [[ "${NETWORKTOOLS_KEEP_SYMBOLS:-0}" == "1" ]]; then
  MACDEPLOYQT_ARGS+=(-no-strip)
fi
macdeployqt "$APP_PATH" "${MACDEPLOYQT_ARGS[@]}"

bundle_extra_runtime_deps

rm -rf "$APP_PATH/Contents/MacOS/data"
mkdir -p "$SEED_DIR"
curl -L --fail --silent --show-error "$MANUF_URL" -o "$SEED_PATH"
mkdir -p "$BIN_DIR"
if [[ "${NETWORKTOOLS_BUNDLE_FPING:-0}" == "1" ]]; then
  FPING_SOURCE="$(find_optional_tool fping "$FPING_SOURCE" || true)"
else
  FPING_SOURCE=""
fi
if [[ -n "$FPING_SOURCE" && -f "$FPING_SOURCE" ]]; then
  cp -f "$FPING_SOURCE" "$BIN_DIR/fping"
  chmod 755 "$BIN_DIR/fping"
else
  echo "Optional fping was not bundled; packaged app will use system fping when available or ping fallback." >&2
fi

codesign --force --deep --sign - --timestamp=none "$APP_PATH"
codesign --verify --deep --strict --verbose=1 "$APP_PATH"

ZIP_PATH="$DIST_DIR/$ZIP_BASENAME.zip"
rm -f "$ZIP_PATH"
ditto -c -k --sequesterRsrc --keepParent "$APP_PATH" "$ZIP_PATH"

DMG_PATH="$DIST_DIR/$DMG_BASENAME.dmg"
create_pretty_dmg "$DMG_PATH"

echo "Packaged app: $APP_PATH"
echo "Archive: $ZIP_PATH"
echo "Disk image: $DMG_PATH"
