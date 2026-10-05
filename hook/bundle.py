#!/usr/bin/env python3
"""Relocate the freshly built desktop adapter and its dependency closure.

Only build outputs and installed development libraries are inspected. This is
not an archive installer and must never be pointed at untrusted downloads.
"""
import json
import pathlib
import re
import shutil
import subprocess
import sys

MAC = (r"libkeypass_hardware\.dylib", r"libfido2\.1\.dylib",
       r"libcrypto\.3\.dylib", r"libcbor\.[0-9.]+\.dylib")
LINUX = (r"libkeypass_hardware\.so", r"libfido2\.so\.1",
         r"libcrypto\.so\.3", r"libcbor\.so\.[0-9.]+")
LINUX_SYSTEM = re.compile(r"^(lib(c|m|dl|rt|pthread|stdc\+\+|gcc_s|udev|z|zstd)\.so\.[0-9]+|ld-linux[^/]*\.so\.[0-9]+)$")


def run(*args: str) -> str:
    return subprocess.check_output(args, text=True).strip()


def dependencies(path: pathlib.Path, mac: bool) -> list[str]:
    if mac:
        # First entry is the library's own install name.
        return [line.strip().split(" (", 1)[0] for line in run("otool", "-L", str(path)).splitlines()[2:]]
    return re.findall(r"\(NEEDED\).*\[([^\]]+)\]", run("readelf", "-d", str(path)))


def is_system(name: str, mac: bool) -> bool:
    return (name.startswith(("/usr/lib/", "/System/Library/")) if mac
            else bool(LINUX_SYSTEM.fullmatch(name)))


def bundle(source: pathlib.Path, output: pathlib.Path) -> dict:
    mac = sys.platform == "darwin"
    if not mac and sys.platform != "linux":
        raise ValueError("hardware bundling supports macOS and Linux")
    patterns = MAC if mac else LINUX
    output.mkdir(parents=True, exist_ok=True)
    pending = [(source.name, source)]
    copied = set()
    inputs = set()
    while pending:
        name, original = pending.pop()
        if name in copied:
            continue
        if not any(re.fullmatch(pattern, name) for pattern in patterns):
            raise ValueError(f"unexpected native dependency {name}")
        if original != source:
            inputs.update((str(original.absolute()), str(original.resolve())))
        target = output / name
        if target.is_symlink():
            raise ValueError(f"bundle target is a symlink: {target}")
        stage = output / (name + ".tmp")
        shutil.copyfile(original, stage)
        stage.replace(target)
        target.chmod(0o755)
        copied.add(name)
        deps = dependencies(original, mac)
        # ldd is used only on the trusted freshly built library, never archives.
        resolved = {} if mac else dict(re.findall(r"^\s*(\S+) => (\S+)", run("ldd", str(original)), re.M))
        for dep in deps:
            if is_system(dep, mac):
                continue
            path = pathlib.Path(dep if mac else resolved.get(dep, ""))
            if not path.is_absolute() or not path.is_file():
                raise ValueError(f"cannot resolve native dependency {dep}")
            pending.append((path.name, path))
            if mac:
                subprocess.run(["install_name_tool", "-change", dep, f"@loader_path/{path.name}", str(target)], check=True)
        if mac:
            subprocess.run(["install_name_tool", "-id", f"@rpath/{name}", str(target)], check=True)
            load = run("otool", "-l", str(target))
            for rpath in re.findall(r"cmd LC_RPATH\s+cmdsize \d+\s+path (.+) \(offset", load):
                subprocess.run(["install_name_tool", "-delete_rpath", rpath, str(target)], check=True)
            # Rewriting invalidates existing signatures. Release signing follows.
            subprocess.run(["codesign", "--force", "--sign", "-", str(target)], check=True)
        else:
            subprocess.run(["patchelf", "--set-rpath", "$ORIGIN", str(target)], check=True)
    if len(copied) != 4 or any(sum(bool(re.fullmatch(p, n)) for n in copied) != 1 for p in patterns):
        raise ValueError("expected exactly the adapter, libfido2, libcrypto and libcbor")
    for name in copied:
        for dep in dependencies(output / name, mac):
            if not is_system(dep, mac) and (dep.removeprefix("@loader_path/") not in copied or (mac and not dep.startswith("@loader_path/"))):
                raise ValueError(f"unbundled dependency {dep}")
    return {"libraries": sorted(copied), "inputs": sorted(inputs)}


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: bundle.py BUILT_LIBRARY OUTPUT_DIRECTORY")
    print(json.dumps(bundle(pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]))))
