#!/usr/bin/env python3
"""Fetch pinned, checksum-verified Linux cores for GitHub release packaging."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import tarfile
import time
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parent.parent
CORES = {
    "paqet": {"version": "v1.0.0-alpha.21", "repository": "hanselime/paqet", "license": "MIT", "format": "tar", "asset": "paqet-linux-{arch}-v1.0.0-alpha.21.tar.gz", "member": "paqet_linux_{arch}", "hashes": {
        "amd64": "4f2f69e0493746726598485ef18df43372470a1514f8021594137e522f0f4fc7",
        "arm64": "be5c7b35a0a93832063e1dc7fddeb76d4597fb9de76abdfdf7b8574b775e3885"}},
    "xray": {"version": "v26.10.10", "repository": "XTLS/Xray-core", "license": "MPL-2.0", "format": "zip", "asset": {"amd64": "Xray-linux-64.zip", "arm64": "Xray-linux-arm64-v8a.zip"}, "member": "xray", "hashes": {
        "amd64": "72a5fde819713a103c6fc26a87aa025c1518c918a34eba4bc38d64dc0728e5d9",
        "arm64": "58e339e67827220175b3a1c6f66f48ccd086b79209f30ba1c0bcb47885d4c22a"}},
    "hysteria": {"version": "app/v2.13.0", "repository": "HyNetworks/hysteria", "license": "MIT", "format": "elf", "asset": "hysteria-linux-{arch}", "member": "", "hashes": {
        "amd64": "907ba8c9693edb104b20582681fb7dc15639d5b64a9cbb616a7b539190a86691",
        "arm64": "a68a61a84452ca250ce0368202521965ca9cc9d801a404f1dc9008ac6cf677a7"}},
}


def download(url, limit=100 * 1024 * 1024):
    for attempt in range(3):
        try:
            request = urllib.request.Request(url, headers={"User-Agent": "HESAR-release-builder"})
            with urllib.request.urlopen(request, timeout=90) as response:
                data = response.read(limit + 1)
            if len(data) > limit:
                raise ValueError("Download exceeds size limit")
            return data
        except OSError:
            if attempt == 2:
                raise
            time.sleep(2)


def extract(data, spec, arch):
    member = spec["member"].format(arch=arch)
    if spec["format"] == "tar":
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
            files = [f for f in archive.getmembers() if f.name == member]
            if len(files) != 1 or not files[0].isfile() or files[0].size > 100 * 1024 * 1024:
                raise ValueError("Invalid core archive member")
            data = archive.extractfile(files[0]).read()
    elif spec["format"] == "zip":
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            files = [f for f in archive.infolist() if f.filename == member]
            if len(files) != 1 or files[0].is_dir() or files[0].file_size > 100 * 1024 * 1024:
                raise ValueError("Invalid core ZIP member")
            data = archive.read(files[0])
    machine = b"\x3e\x00" if arch == "amd64" else b"\xb7\x00"
    if len(data) < 1_000_000 or data[:6] != b"\x7fELF\x02\x01" or data[18:20] != machine:
        raise ValueError("Core is not the expected Linux ELF64 architecture")
    return data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "release/vendor")
    parser.add_argument("--arch", choices=("amd64", "arm64", "both"), default="both")
    args = parser.parse_args()
    arches = ("amd64", "arm64") if args.arch == "both" else (args.arch,)
    manifest = {}
    for name, spec in CORES.items():
        manifest[name] = {k: spec[k] for k in ("version", "repository", "license")}
        manifest[name]["source"] = f"https://github.com/{spec['repository']}/tree/{spec['version']}"
        manifest[name]["binaries"] = {}
        for arch in arches:
            asset = spec["asset"][arch] if isinstance(spec["asset"], dict) else spec["asset"].format(arch=arch)
            url = f"https://github.com/{spec['repository']}/releases/download/{spec['version']}/{asset}"
            data = download(url)
            if hashlib.sha256(data).hexdigest() != spec["hashes"][arch]:
                raise ValueError(f"{name}/{arch}: upstream asset checksum mismatch")
            binary = extract(data, spec, arch)
            destination = args.output / arch / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(binary)
            destination.chmod(0o755)
            manifest[name]["binaries"][arch] = {"asset": url, "asset_sha256": spec["hashes"][arch], "binary_sha256": hashlib.sha256(binary).hexdigest()}
            print(f"Verified {name} {spec['version']} {arch}", flush=True)
        license_file = "LICENSE.md" if name == "hysteria" else "LICENSE"
        license_data = download(f"https://raw.githubusercontent.com/{spec['repository']}/{spec['version']}/{license_file}", 100_000)
        (args.output / f"LICENSE-{name}.txt").write_bytes(license_data)
    (args.output / "CORE-VERSIONS.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
