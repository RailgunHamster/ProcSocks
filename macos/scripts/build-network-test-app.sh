#!/bin/bash
set -euo pipefail
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP="$PROJECT_DIR/dist/ProcSocks Network Test.app"
mkdir -p "$APP/Contents/MacOS"
TEST_ARCH=$(/usr/bin/uname -m)
/usr/bin/swiftc -parse-as-library -warnings-as-errors -O -target "$TEST_ARCH-apple-macos13.0" \
    "$PROJECT_DIR/gui/NetworkTest.swift" \
    "$PROJECT_DIR/gui/Sources/ProcSocksKit/HTTPResponseAccumulator.swift" \
    -o "$APP/Contents/MacOS/ProcSocksNetworkTest"
cat > "$APP/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>com.procsocks.network-test</string>
<key>CFBundleName</key><string>ProcSocks Network Test</string>
<key>CFBundleExecutable</key><string>ProcSocksNetworkTest</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleVersion</key><string>1</string>
<key>LSMinimumSystemVersion</key><string>13.0</string>
<key>NSHighResolutionCapable</key><true/>
</dict></plist>
PLIST
/usr/bin/codesign --force --sign - "$APP"
/usr/bin/codesign --verify --deep --strict "$APP"
printf 'Built: %s\n' "$APP"
