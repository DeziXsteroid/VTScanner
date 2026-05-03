#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
APP_SOURCE="${1:-$ROOT_DIR/cpp/dist/Network Tools.app}"
APP_TARGET="/Applications/Network Tools.app"
APP_SUPPORT_DIR="$HOME/Library/Application Support/NetWorkTools"
DATA_DIR="$APP_SUPPORT_DIR/data"
SEED_PATH="$APP_SOURCE/Contents/Resources/data/manuf"
MANUF_PATH="$DATA_DIR/manuf"
MANUF_URL="https://www.wireshark.org/download/automated/data/manuf"

if [[ ! -d "$APP_SOURCE" ]]; then
  echo "App bundle not found: $APP_SOURCE" >&2
  exit 1
fi

mkdir -p "$DATA_DIR"
rm -rf "$APP_TARGET"
cp -R "$APP_SOURCE" "$APP_TARGET"
codesign --force --deep --sign - --timestamp=none "$APP_TARGET"
codesign --verify --deep --strict --verbose=1 "$APP_TARGET"

if [[ -f "$SEED_PATH" ]]; then
  cp "$SEED_PATH" "$MANUF_PATH"
else
  curl -L --fail --silent --show-error "$MANUF_URL" -o "$MANUF_PATH"
fi

echo "Installed app: $APP_TARGET"
echo "Vendor DB: $MANUF_PATH"
echo "Run with: open \"$APP_TARGET\""
