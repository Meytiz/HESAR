#!/usr/bin/env python3
"""Package the panel, local agent and verified cores into complete Linux releases."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parent.parent


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def tool_output(command):
    try:
        return subprocess.check_output(command, cwd=ROOT, text=True, stderr=subprocess.DEVNULL).strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--repository", default="Meytiz/HESAR")
    args = parser.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,95}", args.version):
        parser.error("Invalid build version")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", args.repository):
        parser.error("Repository must be owner/name")
    release = ROOT / "release"
    script = (ROOT / "scripts/install-hesar.sh").read_text(encoding="utf-8")
    script = re.sub(r'^VERSION=".*"$', f'VERSION="{args.version}"', script, flags=re.M)
    script = re.sub(r'^HESAR_REPOSITORY=".*"$', f'HESAR_REPOSITORY="{args.repository}"', script, flags=re.M)
    identity = "^https://github\\.com/" + re.escape(args.repository) + "/\\.github/workflows/build\\.yml@refs/tags/.*$"
    script = re.sub(r'^COSIGN_IDENTITY_REGEXP=".*"$', lambda _: f'COSIGN_IDENTITY_REGEXP="{identity}"', script, flags=re.M)
    (release / "install-hesar.sh").write_text(script, encoding="utf-8", newline="\n")
    metadata = {"version": args.version, "repository": args.repository,
                "commit": tool_output(["git", "rev-parse", "HEAD"]), "toolchain": tool_output(["go", "version"]),
                "managementPanel": "HTTP", "applicationTraffic": "TCP", "managedCarriers": ["gre", "ipip", "paqet", "xray", "hysteria"],
                "sourceModified": bool(tool_output(["git", "status", "--porcelain"])),
                "signature": "Only the GitHub tag workflow signs releases. Local QA artifacts are unsigned."}
    (release / "BUILDINFO.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    outputs = [release / "install-hesar.sh", release / "BUILDINFO.json"]
    for arch, machine in (("amd64", b"\x3e\x00"), ("arm64", b"\xb7\x00")):
        files = {f"hesar-linux-{arch}": release / f"hesar-linux-{arch}",
                 f"hesar-agent-linux-{arch}": release / f"hesar-agent-linux-{arch}",
                 "install-hesar.sh": release / "install-hesar.sh", "BUILDINFO.json": release / "BUILDINFO.json",
                 "CORE-VERSIONS.json": release / "vendor/CORE-VERSIONS.json",
                 "README.md": ROOT / "README.md", "LICENSE": ROOT / "LICENSE"}
        for name in ("paqet", "xray", "hysteria"):
            files[f"cores/{name}"] = release / "vendor" / arch / name
            files[f"licenses/LICENSE-{name}.txt"] = release / "vendor" / f"LICENSE-{name}.txt"
        files.update({p.relative_to(ROOT).as_posix(): p for p in (ROOT / "docs").rglob("*") if p.is_file()})
        for name, path in files.items():
            if not path.is_file():
                parser.error(f"Missing package member: {name}")
            if name.startswith(("hesar-linux", "hesar-agent", "cores/")):
                header = path.read_bytes()[:20]
                if path.stat().st_size < 1_000_000 or header[:6] != b"\x7fELF\x02\x01" or header[18:20] != machine:
                    parser.error(f"Invalid Linux {arch} ELF: {name}")
        archive = release / f"hesar-linux-{arch}.tar.gz"
        with tarfile.open(archive, "w:gz", format=tarfile.PAX_FORMAT) as tar:
            for name, path in files.items():
                info = tar.gettarinfo(str(path), arcname=name)
                info.mode = 0o755 if name.startswith(("hesar-linux", "hesar-agent", "cores/")) or name == "install-hesar.sh" else 0o644
                info.uid = info.gid = 0
                info.uname = info.gname = ""
                with path.open("rb") as stream:
                    tar.addfile(info, stream)
            data = "".join(f"{digest(path)}  {name}\n" for name, path in files.items()).encode("ascii")
            info = tarfile.TarInfo("checksums-sha256.txt")
            info.size, info.mode = len(data), 0o644
            tar.addfile(info, io.BytesIO(data))
        outputs.append(archive)
    (release / "checksums-sha256.txt").write_text("".join(f"{digest(p)}  {p.name}\n" for p in outputs), encoding="ascii", newline="\n")
    print("Packaged complete Linux amd64 and arm64 releases")


if __name__ == "__main__":
    main()
