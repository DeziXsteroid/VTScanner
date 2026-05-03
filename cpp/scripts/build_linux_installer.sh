#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CPP_DIR="$ROOT_DIR/cpp"
DIST_DIR="$CPP_DIR/dist/installers"
STUB_PATH="$CPP_DIR/installer/linux/bootstrap.stub.sh"
OUT_PATH="$DIST_DIR/Network-Tools-1.0-linux-bootstrap.run"
TMP_DIR="$(mktemp -d)"
PAYLOAD_ROOT="$TMP_DIR/payload"
MANUF_URL="https://www.wireshark.org/download/automated/data/manuf"
MANUF_PATH="$PAYLOAD_ROOT/manuf"

cleanup() {
  rm -rf "$TMP_DIR"
}

trap cleanup EXIT

mkdir -p "$DIST_DIR" "$PAYLOAD_ROOT"

rsync -a \
  --exclude 'build' \
  --exclude 'dist' \
  --exclude '.venv-packaging' \
  --exclude '.venv-packaging-win' \
  --exclude 'tools' \
  "$CPP_DIR/" "$PAYLOAD_ROOT/cpp/"

cp "$ROOT_DIR/README.md" "$PAYLOAD_ROOT/README.md"
cp "$CPP_DIR/PORT_SPEC.md" "$PAYLOAD_ROOT/PORT_SPEC.md"
curl -L --fail --silent --show-error "$MANUF_URL" -o "$MANUF_PATH"

tar -czf "$TMP_DIR/payload.tar.gz" -C "$TMP_DIR" payload
sed 's/__APP_VERSION__/1.0/g' "$STUB_PATH" > "$OUT_PATH"
printf '\n' >> "$OUT_PATH"
cat "$TMP_DIR/payload.tar.gz" >> "$OUT_PATH"
chmod +x "$OUT_PATH"

echo "Linux bootstrap installer: $OUT_PATH"
