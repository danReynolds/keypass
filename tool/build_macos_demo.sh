#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
kp_demo_app="$PWD/build/demo/Keypass Demo.app"
mkdir -p "$kp_demo_app/Contents/MacOS" "$kp_demo_app/Contents/Resources"
# Domain is empty by default. The unsigned development build can check the host
# but cannot accidentally create a passkey against an invented RP identity.
python3 - "$kp_demo_app" <<'PY'
import os,plistlib,re,sys
from pathlib import Path
app=Path(sys.argv[1]); domain=os.environ.get('KEYPASS_DEMO_DOMAIN','').lower()
if domain and (not re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?',domain) or '.' not in domain or '..' in domain):
 raise SystemExit('Invalid KEYPASS_DEMO_DOMAIN')
info={'CFBundleIdentifier':os.environ.get('KEYPASS_DEMO_BUNDLE_ID','dev.keypass.demo'),'CFBundleExecutable':'KeypassDemo','CFBundleName':'Keypass Demo','CFBundleDisplayName':'Keypass Demo','CFBundlePackageType':'APPL','CFBundleVersion':'1','CFBundleShortVersionString':'0.1','LSMinimumSystemVersion':'15.0','KeypassDomain':domain,'NSHighResolutionCapable':True}
(app/'Contents/Info.plist').write_bytes(plistlib.dumps(info))
entitlements={}
if domain:
 team=os.environ.get('KEYPASS_DEMO_TEAM_ID','')
 if not team or not os.environ.get('KEYPASS_DEMO_SIGN_ID'): raise SystemExit('Configured passkey builds require KEYPASS_DEMO_TEAM_ID and KEYPASS_DEMO_SIGN_ID')
 entitlements={'com.apple.developer.associated-domains':['webcredentials:'+domain], 'com.apple.developer.team-identifier':team,'com.apple.application-identifier':team+'.'+info['CFBundleIdentifier']}
Path('build/demo/entitlements.plist').write_bytes(plistlib.dumps(entitlements))
if not os.environ.get('KEYPASS_DEMO_PROFILE'):
 (app/'Contents/embedded.provisionprofile').unlink(missing_ok=True)
PY
dart --suppress-analytics compile exe -Dkeypass.hardware.manual_bundle=true tool/demo/worker.dart -o "$kp_demo_app/Contents/Resources/keypass-demo-worker"
xcrun swiftc -swift-version 5 -target arm64-apple-macos15.0 native/apple/Keypass.swift native/apple/DemoHost/main.swift -o "$kp_demo_app/Contents/MacOS/KeypassDemo"
if [ -n "${KEYPASS_DEMO_PROFILE:-}" ]; then
  cp "$KEYPASS_DEMO_PROFILE" "$kp_demo_app/Contents/embedded.provisionprofile"
fi
kp_demo_identity="${KEYPASS_DEMO_SIGN_ID:--}"
codesign --force --sign "$kp_demo_identity" "$kp_demo_app/Contents/Resources/keypass-demo-worker"
codesign --force --sign "$kp_demo_identity" --entitlements build/demo/entitlements.plist "$kp_demo_app"
codesign --verify --strict "$kp_demo_app"
printf '%s\n' "$kp_demo_app"
