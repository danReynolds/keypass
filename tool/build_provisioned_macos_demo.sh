#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
. ./demo/apple/demo.env
kp_demo_ruby="${KEYPASS_DEMO_RUBY:-ruby}"
if ! "$kp_demo_ruby" -e 'require "xcodeproj"; require "date"' >/dev/null 2>&1; then
  if [ -z "${KEYPASS_DEMO_RUBY:-}" ] && /usr/bin/ruby -e 'require "xcodeproj"; require "date"' >/dev/null 2>&1; then
    kp_demo_ruby=/usr/bin/ruby
  else
    printf '%s\n' 'A Ruby runtime with working xcodeproj and date gems is required.' >&2
    exit 1
  fi
fi
"$kp_demo_ruby" tool/generate_macos_demo_project.rb
mkdir -p build/demo-xcode
dart --suppress-analytics compile exe -Dkeypass.hardware.manual_bundle=true tool/demo/worker.dart -o build/demo-xcode/keypass-demo-worker
if ! xcodebuild -project build/demo-xcode/KeypassDemo.xcodeproj \
  -scheme KeypassDemo -configuration Debug -destination 'platform=macOS,arch=arm64' \
  -derivedDataPath build/demo-xcode/DerivedData \
  -allowProvisioningUpdates -allowProvisioningDeviceRegistration \
  CONFIGURATION_BUILD_DIR="$PWD/build/demo-signed" build > build/demo-xcode/build.log 2>&1; then
  tail -60 build/demo-xcode/build.log
  exit 1
fi
codesign --verify --deep --strict 'build/demo-signed/Keypass Demo.app'
printf '%s\n' "$PWD/build/demo-signed/Keypass Demo.app"
