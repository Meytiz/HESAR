#!/usr/bin/env bash
# Install complete GitHub release bundles; no compiler or protocol setup on servers.
set -euo pipefail
HESAR_REPOSITORY="Meytiz/HESAR"
VERSION="development"
COSIGN_IDENTITY_REGEXP="^https://github\.com/Meytiz/HESAR/\.github/workflows/build\.yml@refs/tags/.*$"
COSIGN_OIDC_ISSUER="https://token.actions.githubusercontent.com"
LIB_DIR="${LIB_DIR:-/usr/local/lib/hesar}"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
CONFIG_DIR="${CONFIG_DIR:-/etc/hesar}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

architecture() {
    case "$(uname -m)" in
        x86_64) BIN_ARCH=amd64 ;;
        aarch64|arm64) BIN_ARCH=arm64 ;;
        *) echo 'Supported architectures: Linux amd64 and arm64.' >&2; return 1 ;;
    esac
}

verify_signature() {
    local manifest="$1" base="$2" temp
    if ! command -v cosign >/dev/null; then
        echo 'Cosign is unavailable: SHA-256 verifies integrity, not publisher identity.' >&2
        return 0
    fi
    temp=$(mktemp -d)
    if cosign verify-blob --help | grep -q -- '--new-bundle-format'; then
        curl -fsSL --max-time 60 "$base.sigstore.json" -o "$temp/bundle" || { rm -rf -- "$temp"; return 1; }
        cosign verify-blob --new-bundle-format=true --bundle "$temp/bundle" \
            --certificate-identity-regexp "$COSIGN_IDENTITY_REGEXP" \
            --certificate-oidc-issuer "$COSIGN_OIDC_ISSUER" "$manifest" || { rm -rf -- "$temp"; return 1; }
    else
        curl -fsSL --max-time 60 "$base.sig" -o "$temp/signature" || { rm -rf -- "$temp"; return 1; }
        curl -fsSL --max-time 60 "$base.pem" -o "$temp/certificate" || { rm -rf -- "$temp"; return 1; }
        cosign verify-blob --signature "$temp/signature" --certificate "$temp/certificate" \
            --certificate-identity-regexp "$COSIGN_IDENTITY_REGEXP" \
            --certificate-oidc-issuer "$COSIGN_OIDC_ISSUER" "$manifest" || { rm -rf -- "$temp"; return 1; }
    fi
    rm -rf -- "$temp"
}

# Run in a subshell so cleanup is scoped to this operation. Only allowlisted
# regular members are streamed, never archive paths, links, owners or scripts.
install_from_artifact() (
    local artifact="$1" stage generation hash
    test -f "$artifact" || { echo 'Release archive not found.' >&2; return 1; }
    mkdir -p -- "$LIB_DIR/releases" "$INSTALL_DIR" || return 1
    chmod 0755 "$LIB_DIR" "$LIB_DIR/releases" || return 1
    stage=$(mktemp -d "$LIB_DIR/releases/.staging.XXXXXXXX") || return 1
    trap 'rm -rf -- "$stage"' EXIT
    # Explicit status handling is required: Bash disables errexit inside a
    # function invoked from an if-condition, including this subshell.
    python3 - "$artifact" "$stage" "$BIN_ARCH" <<'PY' || return 1
import hashlib, re, sys, tarfile
from pathlib import Path
artifact, stage, arch = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
external = artifact.parent / "checksums-sha256.txt"
if external.exists():
    entries = [line.split() for line in external.read_text().splitlines()]
    matches = [e[0] for e in entries if len(e) == 2 and e[1] == f"hesar-linux-{arch}.tar.gz"]
    if len(matches) != 1 or not re.fullmatch(r"[0-9a-fA-F]{64}", matches[0]):
        raise SystemExit("Exactly one archive checksum is required")
    with artifact.open("rb") as stream:
        actual = hashlib.file_digest(stream, "sha256").hexdigest()
    if actual != matches[0].lower():
        raise SystemExit("Archive checksum mismatch; installation unchanged")
else:
    print("Offline archive has no adjacent publisher checksum; use a trusted release", file=sys.stderr)
names = {f"hesar-linux-{arch}": "hesar", f"hesar-agent-linux-{arch}": "hesar-agent",
         "cores/paqet": "cores/paqet", "cores/xray": "cores/xray", "cores/hysteria": "cores/hysteria",
         "CORE-VERSIONS.json": "CORE-VERSIONS.json"}
machine = b"\x3e\x00" if arch == "amd64" else b"\xb7\x00"
with tarfile.open(artifact, "r:gz") as archive:
    def read(name, limit):
        files = [f for f in archive.getmembers() if f.name == name]
        if len(files) != 1 or not files[0].isfile() or not 0 < files[0].size <= limit:
            raise SystemExit("Invalid or missing regular release member: " + name)
        return archive.extractfile(files[0]).read()
    manifest = read("checksums-sha256.txt", 64000).decode("ascii")
    hashes = {}
    for line in manifest.splitlines():
        parts = line.split()
        if len(parts) != 2 or not re.fullmatch(r"[0-9a-f]{64}", parts[0]) or parts[1] in hashes:
            raise SystemExit("Invalid internal checksum manifest")
        hashes[parts[1]] = parts[0]
    for source, target in names.items():
        data = read(source, 100 * 1024 * 1024)
        if hashlib.sha256(data).hexdigest() != hashes.get(source):
            raise SystemExit("Member checksum mismatch: " + source)
        executable = source != "CORE-VERSIONS.json"
        if executable and (len(data) < 1_000_000 or data[:6] != b"\x7fELF\x02\x01" or data[18:20] != machine):
            raise SystemExit("Wrong architecture or incomplete ELF binary: " + source)
        dest = stage / target
        dest.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        dest.write_bytes(data)
        dest.chmod(0o755 if executable else 0o644)
PY
    hash=$(sha256sum -- "$artifact") || return 1
    hash="${hash%% *}"
    generation="$LIB_DIR/releases/$hash"
    chown -R 0:0 "$stage" || return 1
    chmod 0755 "$stage" || return 1
    # Repeated installation uses the same verified generation. Existing
    # generations are root-owned; refuse to reuse a link.
    if [ -e "$generation" ] || [ -L "$generation" ]; then
        test -d "$generation" && test ! -L "$generation" || return 1
        diff -r "$stage" "$generation" >/dev/null || { echo 'Existing generation differs.' >&2; return 1; }
    else
        mv -- "$stage" "$generation" || return 1
        stage=$(mktemp -d "$LIB_DIR/releases/.staging.XXXXXXXX") || return 1
    fi
    ln -s "$generation" "$stage/current" || return 1
    mv -Tf -- "$stage/current" "$LIB_DIR/current" || return 1
    # /usr/local/bin may be a different filesystem: stage its link there.
    local link_dir
    link_dir=$(mktemp -d "$INSTALL_DIR/.hesar-link.XXXXXXXX") || return 1
    ln -s "$LIB_DIR/current/hesar" "$link_dir/hesar" || { rmdir "$link_dir"; return 1; }
    mv -Tf -- "$link_dir/hesar" "$INSTALL_DIR/hesar" || { rm -f "$link_dir/hesar"; rmdir "$link_dir"; return 1; }
    rmdir "$link_dir" || return 1
    echo "Installed verified complete $BIN_ARCH bundle."
)

install_dependencies() {
    test "$(uname -s)" = Linux || { echo 'Linux with systemd is required.' >&2; return 1; }
    command -v systemctl >/dev/null || { echo 'systemd is required.' >&2; return 1; }
    command -v apt-get >/dev/null || { echo 'Supported hosts: Debian 12+ or Ubuntu 24.04+.' >&2; return 1; }
    local ready=1 tool
    for tool in python3 ip iptables ping curl sysctl; do command -v "$tool" >/dev/null || ready=0; done
    if [ "$ready" = 1 ] && python3 -c 'import sys;sys.exit(0 if sys.version_info >= (3,11) else 1)'; then return 0; fi
    DEBIAN_FRONTEND=noninteractive apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        ca-certificates curl python3 iproute2 iptables iputils-ping
    python3 -c 'import sys; assert sys.version_info >= (3, 11), "Python 3.11+ is required (Debian 12+/Ubuntu 24.04+)"'
}

install_services() {
    if ! id hesar >/dev/null 2>&1; then
        useradd --system --home-dir "$CONFIG_DIR" --shell /usr/sbin/nologin hesar
    fi
    mkdir -p "$CONFIG_DIR/data" /var/log/hesar /var/lib/hesar-agent
    chown -R hesar:hesar "$CONFIG_DIR" /var/log/hesar
    chmod 0700 "$CONFIG_DIR" "$CONFIG_DIR/data" /var/log/hesar
    chown root:hesar /var/lib/hesar-agent
    chmod 0750 /var/lib/hesar-agent
    cat > /etc/systemd/system/hesar-agent.service <<EOF
[Unit]
Description=HESAR managed network agent
After=network-online.target
Wants=network-online.target hesar.service
Before=hesar.service
[Service]
Type=notify
NotifyAccess=main
TimeoutStartSec=90
User=root
Group=hesar
UMask=0027
ExecStart=$LIB_DIR/current/hesar-agent -cores $LIB_DIR/current/cores -user hesar
Restart=on-failure
RestartSec=3
RuntimeDirectory=hesar-agent
RuntimeDirectoryMode=0750
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/lib/hesar-agent /run/hesar-agent
NoNewPrivileges=true
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE CAP_SETUID CAP_SETGID CAP_SETPCAP CAP_CHOWN CAP_DAC_OVERRIDE CAP_FOWNER CAP_KILL
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK AF_PACKET
[Install]
WantedBy=multi-user.target
EOF
    cat > /etc/systemd/system/hesar.service <<EOF
[Unit]
Description=HESAR HTTP panel and authenticated tunnels
After=network-online.target hesar-agent.service
Requires=hesar-agent.service
BindsTo=hesar-agent.service
PartOf=hesar-agent.service
[Service]
Type=simple
User=hesar
Group=hesar
UMask=0077
WorkingDirectory=$CONFIG_DIR
ExecStart=$LIB_DIR/current/hesar -config $CONFIG_DIR/data/config.json
Restart=on-failure
RestartSec=3
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=$CONFIG_DIR /var/log/hesar
NoNewPrivileges=true
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable hesar-agent.service hesar.service
    systemctl restart hesar-agent.service
    echo 'HTTP panel uses port 8443 by default. Initial login credentials appear once in: sudo journalctl -u hesar -n 50'
    echo 'Create tunnels, generate keys, import peer setup, and Start/Stop only through the panel.'
}

install_release() {
    [ "$EUID" -eq 0 ] || { echo 'Run with sudo.' >&2; return 1; }
    architecture
    install_dependencies
    local artifact="${1:-}" temp="" base
    if [ -z "$artifact" ]; then
        artifact="$SCRIPT_DIR/hesar-linux-$BIN_ARCH.tar.gz"
        if [ ! -f "$artifact" ] || [ "${2:-}" = latest ]; then
            temp=$(mktemp -d)
            base="https://github.com/$HESAR_REPOSITORY/releases/latest/download"
            curl -fSL --retry 3 --max-time 600 "$base/hesar-linux-$BIN_ARCH.tar.gz" -o "$temp/hesar-linux-$BIN_ARCH.tar.gz" || { rm -rf -- "$temp"; return 1; }
            curl -fsSL --max-time 60 "$base/checksums-sha256.txt" -o "$temp/checksums-sha256.txt" || { rm -rf -- "$temp"; return 1; }
            verify_signature "$temp/checksums-sha256.txt" "$base/checksums-sha256.txt" || { rm -rf -- "$temp"; return 1; }
            artifact="$temp/hesar-linux-$BIN_ARCH.tar.gz"
        fi
    fi
    install_from_artifact "$artifact" || { [ -z "$temp" ] || rm -rf -- "$temp"; return 1; }
    [ -z "$temp" ] || rm -rf -- "$temp"
    install_services
}

if [[ "${BASH_SOURCE[0]}" != "$0" ]]; then return 0; fi
case "${1:---quickstart}" in
    --quickstart) install_release ;;
    --update) install_release "" latest ;;
    --offline) test "$#" -eq 2; install_release "$2" ;;
    --status) systemctl status hesar hesar-agent --no-pager ;;
    --logs) journalctl -u hesar -u hesar-agent -n 100 --no-pager ;;
    *) echo 'Usage: install-hesar.sh [--quickstart | --offline <complete-release.tar.gz> | --update | --status | --logs]' >&2; exit 1 ;;
esac
