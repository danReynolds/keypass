#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
mkdir -p build/native/KeypassSmoke.app/Contents/MacOS build/native/KeypassSmoke-iOS.app
cat > build/native/KeypassSmoke.app/Contents/Info.plist <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>CFBundleIdentifier</key><string>dev.keypass.native-smoke</string><key>CFBundleExecutable</key><string>KeypassSmoke</string><key>CFBundlePackageType</key><string>APPL</string><key>LSMinimumSystemVersion</key><string>15.0</string></dict></plist>
PLIST
xcrun swiftc -swift-version 5 -target arm64-apple-macos15.0 native/apple/Keypass.swift native/apple/SmokeHost/main.swift -o build/native/KeypassSmoke.app/Contents/MacOS/KeypassSmoke
KEYPASS_SMOKE_RESULT="$PWD/build/native/apple-macos-smoke.txt" build/native/KeypassSmoke.app/Contents/MacOS/KeypassSmoke
cat build/native/apple-macos-smoke.txt
rg -q '^PASS ' build/native/apple-macos-smoke.txt
cat > build/native/KeypassSmoke-iOS.app/Info.plist <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>CFBundleIdentifier</key><string>dev.keypass.native-smoke</string><key>CFBundleExecutable</key><string>KeypassSmoke</string><key>CFBundleName</key><string>KeypassSmoke</string><key>CFBundleVersion</key><string>1</string><key>CFBundleShortVersionString</key><string>1.0</string><key>CFBundlePackageType</key><string>APPL</string><key>MinimumOSVersion</key><string>18.0</string><key>LSRequiresIPhoneOS</key><true/><key>UIDeviceFamily</key><array><integer>1</integer><integer>2</integer></array><key>UILaunchScreen</key><dict/></dict></plist>
PLIST
xcrun swiftc -swift-version 5 -target arm64-apple-ios18.0-simulator -sdk "$(xcrun --sdk iphonesimulator --show-sdk-path)" native/apple/Keypass.swift native/apple/SmokeHost/main.swift -o build/native/KeypassSmoke-iOS.app/KeypassSmoke
codesign --force --sign - build/native/KeypassSmoke-iOS.app
