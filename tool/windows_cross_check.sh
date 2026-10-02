#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
python3 - <<'PY'
import hashlib
import urllib.request
from pathlib import Path
root = Path('build/native/windows-deps')
root.mkdir(parents=True, exist_ok=True)
files = [
    ('webauthn.h', 'https://raw.githubusercontent.com/microsoft/webauthn/ef82c157125a0490e05f6ea82a7adb1b8e1bad08/webauthn.h', 'da82d5be6b90a2706185ae44ad93649bcefc0f89c97ab930ec4e6f0abb7b2283'),
    ('json.hpp', 'https://raw.githubusercontent.com/nlohmann/json/v3.12.0/single_include/nlohmann/json.hpp', 'aaf127c04cb31c406e5b04a63f1ae89369fccde6d8fa7cdda1ed4f32dfc5de63'),
]
for name, url, digest in files:
    target = root / name
    data = target.read_bytes() if target.exists() else urllib.request.urlopen(url, timeout=30).read()
    if hashlib.sha256(data).hexdigest() != digest:
        raise RuntimeError('Native build dependency checksum mismatch: ' + name)
    target.write_bytes(data)
PY
docker build -f tool/validation/Windows.Dockerfile -t keypass-windows-cross:local .
kp_windows_container=$(docker create keypass-windows-cross:local)
trap 'docker rm "$kp_windows_container" >/dev/null' EXIT
docker cp "$kp_windows_container:/keypass.dll" build/native/keypass.dll
