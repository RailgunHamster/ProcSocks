#!/bin/bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CARGO_BIN="${CARGO:-$(command -v cargo || true)}"
if [ -z "$CARGO_BIN" ]; then CARGO_BIN="$HOME/.cargo/bin/cargo"; fi
SWIFT_BIN="${SWIFT:-/usr/bin/swift}"
APP="$PROJECT_DIR/dist/ProcSocks.app"

cd "$PROJECT_DIR"
"$CARGO_BIN" build --release --locked
"$SWIFT_BIN" build --package-path "$PROJECT_DIR/gui" --configuration release
SWIFT_OUTPUT=$("$SWIFT_BIN" build --package-path "$PROJECT_DIR/gui" --configuration release --show-bin-path)

mkdir -p "$PROJECT_DIR/dist"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$PROJECT_DIR/gui/Info.plist" "$APP/Contents/Info.plist"
cp "$SWIFT_OUTPUT/ProcSocksMenuBar" "$APP/Contents/MacOS/ProcSocksMenuBar"
cp "$PROJECT_DIR/target/release/procsocks" "$APP/Contents/Resources/procsocks"
cp "$PROJECT_DIR/config.macos.example.json" "$APP/Contents/Resources/config.example.json"
cp "$PROJECT_DIR/LICENSE" "$APP/Contents/Resources/LICENSE"

ICONSET=$(mktemp -d "${TMPDIR:-/tmp}/procsocks-icon.XXXXXX")
trap 'rm -rf "$ICONSET"' EXIT
mkdir -p "$ICONSET/ProcSocks.iconset"
"$SWIFT_BIN" "$PROJECT_DIR/gui/BuildIcon.swift" "$ICONSET/ProcSocks.iconset"
/usr/bin/iconutil -c icns "$ICONSET/ProcSocks.iconset" -o "$APP/Contents/Resources/ProcSocks.icns"

/usr/bin/codesign --force --sign - "$APP/Contents/Resources/procsocks"
/usr/bin/codesign --force --sign - "$APP"
/usr/bin/codesign --verify --deep --strict "$APP"
/usr/bin/plutil -lint "$APP/Contents/Info.plist"
printf '\nBuilt: %s\n' "$APP"
