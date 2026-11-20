#!/usr/bin/env bash
# Builds dist/Lens.app (Apple Silicon) and dist/Lens-macos-arm64.zip from a release build.
set -euo pipefail
cd "$(dirname "$0")/.."
VERSION=$(grep -m1 '^version' Cargo.toml | sed 's/.*"\(.*\)"/\1/')
cargo build --release --target aarch64-apple-darwin
rm -rf dist && mkdir -p dist/Lens.app/Contents/{MacOS,Resources}
cp target/aarch64-apple-darwin/release/lens dist/Lens.app/Contents/MacOS/Lens
cp assets/Lens.icns dist/Lens.app/Contents/Resources/Lens.icns
cat > dist/Lens.app/Contents/Info.plist <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleName</key><string>Lens</string>
  <key>CFBundleDisplayName</key><string>Lens</string>
  <key>CFBundleIdentifier</key><string>com.lens.disassembler</string>
  <key>CFBundleExecutable</key><string>Lens</string>
  <key>CFBundleIconFile</key><string>Lens</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>${VERSION}</string>
  <key>CFBundleVersion</key><string>${VERSION}</string>
  <key>LSMinimumSystemVersion</key><string>11.0</string>
  <key>NSHighResolutionCapable</key><true/>
  <key>LSApplicationCategoryType</key><string>public.app-category.developer-tools</string>
  <key>CFBundleDocumentTypes</key><array><dict>
    <key>CFBundleTypeName</key><string>Program</string>
    <key>CFBundleTypeRole</key><string>Viewer</string>
    <key>LSItemContentTypes</key><array><string>public.data</string><string>public.executable</string></array>
  </dict></array>
</dict></plist>
PLIST
# Ad-hoc signature: required for arm64 binaries to launch. Use a Developer ID in CODESIGN_IDENTITY to notarize.
codesign --force --deep --sign "${CODESIGN_IDENTITY:--}" dist/Lens.app
(cd dist && ditto -c -k --keepParent Lens.app Lens-macos-arm64.zip)
echo "Built dist/Lens.app and dist/Lens-macos-arm64.zip (v${VERSION})"
