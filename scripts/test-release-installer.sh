#!/usr/bin/env bash
# Verify bundle validation and atomic replacement without changing host services.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT/scripts/install-hesar.sh"
TEMP=$(mktemp -d)
trap 'rm -rf -- "$TEMP"' EXIT
LIB_DIR="$TEMP/library"
INSTALL_DIR="$TEMP/bin"
BIN_ARCH=amd64
install_from_artifact "$ROOT/release/hesar-linux-amd64.tar.gz"
previous=$(readlink "$LIB_DIR/current")
test -x "$INSTALL_DIR/hesar"
test -x "$LIB_DIR/current/hesar-agent"
for name in paqet xray hysteria; do test -x "$LIB_DIR/current/cores/$name"; done
for case in missing-core tampered-core linked-core duplicate-core wrong-architecture; do
python3 - "$ROOT/release/hesar-linux-amd64.tar.gz" "$TEMP" "$case" <<'PY'
import hashlib,io,sys,tarfile
from pathlib import Path
source, dest = Path(sys.argv[1]), Path(sys.argv[2])
case=sys.argv[3]
with tarfile.open(source) as archive:
    entries = [(f, archive.extractfile(f).read()) for f in archive if f.isfile()]
if case=='wrong-architecture':
    original=next(data for info,data in entries if info.name=='cores/paqet')
    replacement=original[:18]+b'\xb7\x00'+original[20:]
    entries=[(info,data.replace(hashlib.sha256(original).hexdigest().encode(),hashlib.sha256(replacement).hexdigest().encode()) if info.name=='checksums-sha256.txt' else data) for info,data in entries]
with tarfile.open(dest / (case+'.tar.gz'),'w:gz') as out:
        for info,data in entries:
            if info.name=='cores/paqet':
                if case=='missing-core': continue
                if case=='tampered-core': data=data[:-1]+bytes([data[-1]^1])
                if case=='linked-core':
                    link=tarfile.TarInfo(info.name);link.type=tarfile.SYMTYPE;link.linkname='/bin/sh';out.addfile(link);continue
                if case=='wrong-architecture': data=data[:18]+b'\xb7\x00'+data[20:]
                if case=='duplicate-core': out.addfile(info,io.BytesIO(data))
            out.addfile(info,io.BytesIO(data))
PY
    if install_from_artifact "$TEMP/$case.tar.gz" >"$TEMP/$case.log" 2>&1; then
        echo "Installer incorrectly accepted $case" >&2; exit 1
    fi
    test "$(readlink "$LIB_DIR/current")" = "$previous"
    rm -f -- "$TEMP/$case.tar.gz"
done
if install_from_artifact "$ROOT/release/hesar-linux-amd64" >/dev/null 2>&1; then
    echo 'An incomplete standalone binary must not replace the complete bundle.' >&2; exit 1
fi
test "$(readlink "$LIB_DIR/current")" = "$previous"
install_from_artifact "$ROOT/release/hesar-linux-amd64.tar.gz"
test "$(readlink "$LIB_DIR/current")" = "$previous"
echo 'PASS: complete bundle, repeat install, tamper/link/duplicate/missing-core rejection and current-generation preservation'
