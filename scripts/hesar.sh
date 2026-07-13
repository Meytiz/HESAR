#!/usr/bin/env bash
set -euo pipefail

# ──────────────────────────────────────────────────
# Colors
# ──────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
MAGENTA='\033[1;35m'
NC='\033[0m'
BOLD='\033[1m'

# ──────────────────────────────────────────────────
# Paths & Constants
# ──────────────────────────────────────────────────
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/hesar"
DATA_DIR="${CONFIG_DIR}/data"
LOG_FILE="/var/log/hesar.log"
SYSTEMD_FILE="/etc/systemd/system/hesar.service"
SYSCTL_FILE="/etc/sysctl.d/99-hesar-tune.conf"
HESAR_USER="hesar"
REPO_URL="https://github.com/Meytiz/HESAR"
VERSION="1.0.0"

# ──────────────────────────────────────────────────
# Cosign keyless signing parameters
# (Must match identity of the GitHub Actions workflow that signs releases)
# ──────────────────────────────────────────────────
COSIGN_OIDC_ISSUER="https://token.actions.githubusercontent.com"
COSIGN_IDENTITY_REGEXP="^https://github\.com/Meytiz/HESAR/\.github/workflows/build\.yml@refs/tags/.*$"

# ──────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────
get_public_ip() {
    local ip=""
    local services=(
        "https://api.ipify.org"
        "https://icanhazip.com"
        "https://ipinfo.io/ip"
        "https://ifconfig.me/ip"
        "https://checkip.amazonaws.com"
        "https://api.seeip.org"
    )

    for url in "${services[@]}"; do
        ip=$(curl -s -4 --max-time 8 "$url" 2>/dev/null) || continue
        ip=$(echo "$ip" | tr -d '[:space:]')
        if echo "$ip" | grep -qP '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'; then
            echo "$ip"
            return 0
        fi
    done

    echo "YOUR_SERVER_IP"
}

generate_random_string() {
    local length="${1:-16}"
    tr -dc A-Za-z0-9 </dev/urandom 2>/dev/null | head -c "$length" || true
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "  ${RED}[ERROR] Please run as root or with sudo.${NC}"
        exit 1
    fi
}

press_enter() {
    echo ""
    read -rp "  Press Enter to return to menu..." _
}

# ──────────────────────────────────────────────────
# Signature Verification (cosign keyless, tied to GH Actions OIDC identity)
# ──────────────────────────────────────────────────
verify_manifest_signature() {
    local manifest_path="$1"
    local sig_url="$2"
    local pem_url="$3"

    if ! command -v cosign >/dev/null 2>&1; then
        echo -e "  ${YELLOW}[WARN] cosign not installed - skipping signature verification.${NC}"
        echo -e "  ${YELLOW}[WARN] Falling back to checksum-only integrity check.${NC}"
        echo -e "  ${YELLOW}[WARN] Install cosign for full verification: https://docs.sigstore.dev/cosign/installation${NC}"
        return 0
    fi

    local tmp_sig="/tmp/hesar-manifest-$$.sig"
    local tmp_pem="/tmp/hesar-manifest-$$.pem"

    if ! curl -fsSL --max-time 30 -o "${tmp_sig}" "${sig_url}"; then
        echo -e "  ${RED}[ERROR] Failed to download signature file: ${sig_url}${NC}"
        rm -f "${tmp_sig}" "${tmp_pem}"
        return 1
    fi
    if ! curl -fsSL --max-time 30 -o "${tmp_pem}" "${pem_url}"; then
        echo -e "  ${RED}[ERROR] Failed to download certificate file: ${pem_url}${NC}"
        rm -f "${tmp_sig}" "${tmp_pem}"
        return 1
    fi

    if cosign verify-blob \
        --certificate "${tmp_pem}" \
        --signature "${tmp_sig}" \
        --certificate-identity-regexp "${COSIGN_IDENTITY_REGEXP}" \
        --certificate-oidc-issuer "${COSIGN_OIDC_ISSUER}" \
        "${manifest_path}" >/dev/null 2>&1; then
        echo -e "  ${GREEN}---> Cosign signature verified. Manifest origin confirmed.${NC}"
        rm -f "${tmp_sig}" "${tmp_pem}"
        return 0
    else
        echo -e "  ${RED}[ERROR] Cosign signature verification FAILED.${NC}"
        rm -f "${tmp_sig}" "${tmp_pem}"
        return 1
    fi
}

verify_checksum() {
    local bin_path="$1"
    local arch="$2"
    local checksum_url="$3"
    local tmp_checksum="/tmp/hesar-checksums-$$.txt"

    echo -e "  ${YELLOW}---> Downloading checksum manifest...${NC}"

    if ! curl -fsSL --connect-timeout 15 --retry 5 --retry-delay 3 --max-time 60 \
        -o "${tmp_checksum}" "${checksum_url}"; then
        echo -e "  ${RED}[ERROR] Failed to download checksum file: ${checksum_url}${NC}"
        rm -f "${tmp_checksum}"
        return 1
    fi

    if [ ! -s "${tmp_checksum}" ]; then
        echo -e "  ${RED}[ERROR] Checksum file is empty.${NC}"
        rm -f "${tmp_checksum}"
        return 1
    fi

    if ! verify_manifest_signature "${tmp_checksum}" "${checksum_url}.sig" "${checksum_url}.pem"; then
        echo -e "  ${RED}[ERROR] Refusing to trust unsigned/tampered checksum manifest.${NC}"
        rm -f "${tmp_checksum}"
        return 1
    fi

    local expected_hash
    expected_hash=$(grep -E "hesar-linux-${arch}$" "${tmp_checksum}" | awk '{print $1}' | head -1)

    if [ -z "${expected_hash}" ]; then
        echo -e "  ${RED}[ERROR] No checksum entry found for hesar-linux-${arch}.${NC}"
        rm -f "${tmp_checksum}"
        return 1
    fi

    local actual_hash
    actual_hash=$(sha256sum "${bin_path}" | awk '{print $1}')

    rm -f "${tmp_checksum}"

    if [ "${expected_hash}" != "${actual_hash}" ]; then
        echo -e "  ${RED}[ERROR] CHECKSUM MISMATCH - possible tampering or corruption.${NC}"
        echo -e "  ${RED}Expected: ${expected_hash}${NC}"
        echo -e "  ${RED}Actual  : ${actual_hash}${NC}"
        return 1
    fi

    echo -e "  ${GREEN}---> Checksum verified (sha256: ${actual_hash:0:16}...).${NC}"
    return 0
}

# ──────────────────────────────────────────────────
# Self Verification (verify hesar.sh against signed manifest before execution)
# ──────────────────────────────────────────────────
verify_self() {
    local script_path="${1:-$0}"

    if [ ! -f "${script_path}" ]; then
        echo -e "  ${RED}[ERROR] Script file not found: ${script_path}${NC}"
        echo -e "  ${YELLOW}Save the script to disk first, then run: $0 --verify-self <path>${NC}"
        return 1
    fi

    echo -e "  ${YELLOW}---> Verifying integrity of: ${script_path}${NC}"

    local checksum_url="${REPO_URL}/releases/latest/download/checksums-sha256.txt"
    local tmp_checksum="/tmp/hesar-self-checksums-$$.txt"

    if ! curl -fsSL --max-time 30 -o "${tmp_checksum}" "${checksum_url}"; then
        echo -e "  ${RED}[ERROR] Failed to download checksum manifest.${NC}"
        rm -f "${tmp_checksum}"
        return 1
    fi

    if ! verify_manifest_signature "${tmp_checksum}" "${checksum_url}.sig" "${checksum_url}.pem"; then
        echo -e "  ${RED}[ERROR] Refusing to trust unsigned/tampered checksum manifest.${NC}"
        rm -f "${tmp_checksum}"
        return 1
    fi

    local expected_hash
    expected_hash=$(grep -E "hesar\.sh$" "${tmp_checksum}" | awk '{print $1}' | head -1)

    if [ -z "${expected_hash}" ]; then
        echo -e "  ${RED}[ERROR] No checksum entry found for hesar.sh.${NC}"
        rm -f "${tmp_checksum}"
        return 1
    fi

    local actual_hash
    actual_hash=$(sha256sum "${script_path}" | awk '{print $1}')
    rm -f "${tmp_checksum}"

    if [ "${expected_hash}" != "${actual_hash}" ]; then
        echo -e "  ${RED}[ERROR] SELF-VERIFICATION FAILED - script modified or not from an official release.${NC}"
        echo -e "  ${RED}Expected: ${expected_hash}${NC}"
        echo -e "  ${RED}Actual  : ${actual_hash}${NC}"
        return 1
    fi

    echo -e "  ${GREEN}---> Script integrity verified (sha256: ${actual_hash:0:16}...).${NC}"
    return 0
}

# ──────────────────────────────────────────────────
# Banner
# ──────────────────────────────────────────────────
draw_banner() {
    clear
    echo ""
    echo -e "  ${MAGENTA}╦ ╦${NC} ${CYAN}╔═╗${NC} ${GREEN}╔═╗${NC} ${YELLOW}╔═╗${NC} ${RED}╦═╗${NC}    ${BLUE}╔╦╗${NC} ${PURPLE}╦ ╦${NC} ${CYAN}╔╗╔${NC} ${GREEN}╔╗╔${NC} ${YELLOW}╔═╗${NC} ${RED}╦  ${NC}"
    echo -e "  ${MAGENTA}╠═╣${NC} ${CYAN}║╣ ${NC} ${GREEN}╚═╗${NC} ${YELLOW}╠═╣${NC} ${RED}╠╦╝${NC}     ${BLUE}║ ${NC} ${PURPLE}║ ║${NC} ${CYAN}║║║${NC} ${GREEN}║║║${NC} ${YELLOW}║╣ ${NC} ${RED}║  ${NC}"
    echo -e "  ${MAGENTA}╩ ╩${NC} ${CYAN}╚═╝${NC} ${GREEN}╚═╝${NC} ${YELLOW}╩ ╩${NC} ${RED}╩╚═${NC}     ${BLUE}╩ ${NC} ${PURPLE}╚═╝${NC} ${CYAN}╝╚╝${NC} ${GREEN}╝╚╝${NC} ${YELLOW}╚═╝${NC} ${RED}╩═╝${NC}"
    echo ""
    echo -e "  ${WHITE}${BOLD}TCP + KCP + IP/SNI SPOOFING${NC} ${WHITE}|${NC} ${YELLOW}BBR + Auto-Optimizer${NC}"
    echo -e "  ${PURPLE}Version: ${VERSION}${NC}"
    echo ""
}

# ──────────────────────────────────────────────────
# Install Binary
# ──────────────────────────────────────────────────
install_binaries() {
    echo -e "  ${YELLOW}---> Detecting architecture...${NC}"
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64)        BIN_ARCH="amd64" ;;
        aarch64|arm64) BIN_ARCH="arm64" ;;
        *) echo -e "  ${RED}[ERROR] Unsupported arch: $ARCH${NC}"; exit 1 ;;
    esac
    echo -e "  ${GREEN}---> Architecture: ${ARCH} (${BIN_ARCH})${NC}"

    mkdir -p "${INSTALL_DIR}" "${DATA_DIR}"

    if ! id -u "${HESAR_USER}" >/dev/null 2>&1; then
        echo -e "  ${YELLOW}---> Creating system user '${HESAR_USER}'...${NC}"
        useradd -r -s /bin/false -d "${CONFIG_DIR}" "${HESAR_USER}" 2>/dev/null || true
    fi

    systemctl stop hesar 2>/dev/null || true
    sleep 1

    if [ -f "./backend/hesar" ]; then
        echo -e "  ${GREEN}---> Local binary found. Installing...${NC}"
        rm -f "${INSTALL_DIR}/hesar"
        cp ./backend/hesar "${INSTALL_DIR}/hesar"
    elif [ -f "./hesar-linux-${BIN_ARCH}" ]; then
        echo -e "  ${GREEN}---> Offline binary found. Installing...${NC}"
        rm -f "${INSTALL_DIR}/hesar"
        cp "./hesar-linux-${BIN_ARCH}" "${INSTALL_DIR}/hesar"
    else
        echo -e "  ${YELLOW}---> Downloading latest release...${NC}"
        local url="${REPO_URL}/releases/latest/download/hesar-linux-${BIN_ARCH}"
        local checksum_url="${REPO_URL}/releases/latest/download/checksums-sha256.txt"
        rm -f "${INSTALL_DIR}/hesar"

        if curl -fSL --connect-timeout 20 --retry 10 --retry-delay 5 --max-time 300 -o "${INSTALL_DIR}/hesar" "${url}"; then
            echo -e "  ${GREEN}---> Downloaded successfully.${NC}"

            if ! verify_checksum "${INSTALL_DIR}/hesar" "${BIN_ARCH}" "${checksum_url}"; then
                rm -f "${INSTALL_DIR}/hesar"
                echo -e "  ${RED}[ERROR] Aborting install - integrity check failed.${NC}"
                echo -e "  ${YELLOW}---> Trying to build from source...${NC}"
                if command -v go >/dev/null 2>&1 && [ -d "./backend" ]; then
                    (cd backend && go build -ldflags="-s -w" -o "${INSTALL_DIR}/hesar" cmd/hesar/main.go)
                else
                    echo -e "  ${RED}[ERROR] Cannot obtain a verified binary.${NC}"
                    return 1
                fi
            elif ! file "${INSTALL_DIR}/hesar" 2>/dev/null | grep -q "ELF"; then
                echo -e "  ${RED}[ERROR] Downloaded file is not a valid binary.${NC}"
                rm -f "${INSTALL_DIR}/hesar"
                echo -e "  ${YELLOW}---> Trying to build from source...${NC}"
                if command -v go >/dev/null 2>&1 && [ -d "./backend" ]; then
                    (cd backend && go build -ldflags="-s -w" -o "${INSTALL_DIR}/hesar" cmd/hesar/main.go)
                else
                    echo -e "  ${RED}[ERROR] Cannot download or build binary.${NC}"
                    return 1
                fi
            fi
        else
            echo -e "  ${RED}[ERROR] Download failed!${NC}"
            echo -e "  ${YELLOW}---> Trying to build from source...${NC}"
            if command -v go >/dev/null 2>&1 && [ -d "./backend" ]; then
                (cd backend && go build -ldflags="-s -w" -o "${INSTALL_DIR}/hesar" cmd/hesar/main.go)
            else
                echo -e "  ${RED}[ERROR] Cannot download or build binary.${NC}"
                echo -e "  ${YELLOW}Check internet connection or use offline method.${NC}"
                return 1
            fi
        fi
    fi

    chmod +x "${INSTALL_DIR}/hesar"
    echo -e "  ${GREEN}---> Binary installed -> ${INSTALL_DIR}/hesar${NC}"
}

# ──────────────────────────────────────────────────
# Systemd Service Setup
# ──────────────────────────────────────────────────
setup_systemd() {
    echo -e "  ${YELLOW}---> Configuring systemd service...${NC}"

    cat > "${SYSTEMD_FILE}" <<EOF
[Unit]
Description=HESAR Anti-DPI Reverse Tunnel Daemon
After=network.target

[Service]
Type=simple
User=${HESAR_USER}
Group=${HESAR_USER}
WorkingDirectory=${CONFIG_DIR}
ExecStart=${INSTALL_DIR}/hesar -config ${DATA_DIR}/config.json
Restart=always
RestartSec=3
LimitNOFILE=1048576
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=${CONFIG_DIR} ${LOG_FILE}
PrivateTmp=true
Environment="GOMEMLIMIT=512MiB"

[Install]
WantedBy=multi-user.target
EOF

    chown -R "${HESAR_USER}:${HESAR_USER}" "${CONFIG_DIR}"
    touch "${LOG_FILE}"
    chown "${HESAR_USER}:${HESAR_USER}" "${LOG_FILE}"

    systemctl daemon-reload
    systemctl enable hesar
    systemctl restart hesar
    echo -e "  ${GREEN}---> Service activated.${NC}"
}

# ──────────────────────────────────────────────────
# Option 1: Quick Start (GUI + Core)
# ──────────────────────────────────────────────────
quick_start_install() {
    check_root
    echo ""
    install_binaries

    echo -e "  ${YELLOW}---> Generating secure random credentials...${NC}"
    RAND_PORT=$(shuf -i 5000-9999 -n 1 2>/dev/null || echo "8443")
    RAND_USER="admin_$(generate_random_string 4)"
    RAND_PASS="Hesar#$(generate_random_string 12)"
    RAND_JWT="hesar_jwt_$(generate_random_string 32)"

    cat > "${DATA_DIR}/config.json" <<EOF
{
  "admin_username": "${RAND_USER}",
  "admin_password": "${RAND_PASS}",
  "listen_port": ${RAND_PORT},
  "log_path": "${LOG_FILE}",
  "log_max_size_mb": 10,
  "secret_key": "${RAND_JWT}",
  "tunnels": []
}
EOF
    chmod 600 "${DATA_DIR}/config.json"

    setup_systemd
    sleep 3

    PUB_IP=$(get_public_ip)

    echo ""
    echo -e "  ${GREEN}${BOLD}══════════════════════════════════════════════${NC}"
    echo -e "  ${GREEN}${BOLD}   HESAR QUICK START SETUP SUCCESSFUL${NC}"
    echo -e "  ${GREEN}${BOLD}══════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  ${CYAN}GUI Panel Address  :${WHITE}${BOLD} http://${PUB_IP}:${RAND_PORT}/${NC}"
    echo -e "  ${CYAN}Listen Port        :${WHITE} ${RAND_PORT}${NC}"
    echo -e "  ${CYAN}Username           :${YELLOW}${BOLD} ${RAND_USER}${NC}"
    echo -e "  ${CYAN}Password           :${YELLOW}${BOLD} ${RAND_PASS}${NC}"
    echo ""
    echo -e "  ${RED}${BOLD}SAVE THESE CREDENTIALS - They won't be shown again!${NC}"
    echo -e "  ${RED}${BOLD}Change password after first login.${NC}"
    echo ""
}

# ──────────────────────────────────────────────────
# Option 2: Core Only (Daemon Only)
# ──────────────────────────────────────────────────
core_only_install() {
    check_root
    echo ""
    install_binaries

    echo -e "  ${YELLOW}---> Setting up Core daemon configuration...${NC}"
    if [ ! -f "${DATA_DIR}/config.json" ]; then
        RAND_PORT=$(shuf -i 5000-9999 -n 1 2>/dev/null || echo "8443")
        RAND_USER="admin_$(generate_random_string 4)"
        RAND_PASS="Hesar#$(generate_random_string 12)"
        RAND_JWT="hesar_jwt_$(generate_random_string 32)"

        cat > "${DATA_DIR}/config.json" <<EOF
{
  "admin_username": "${RAND_USER}",
  "admin_password": "${RAND_PASS}",
  "listen_port": ${RAND_PORT},
  "log_path": "${LOG_FILE}",
  "log_max_size_mb": 10,
  "secret_key": "${RAND_JWT}",
  "tunnels": []
}
EOF
        chmod 600 "${DATA_DIR}/config.json"
        echo ""
        echo -e "  ${CYAN}Username :${YELLOW}${BOLD} ${RAND_USER}${NC}"
        echo -e "  ${CYAN}Password :${YELLOW}${BOLD} ${RAND_PASS}${NC}"
        echo -e "  ${CYAN}Port     :${WHITE}${BOLD} ${RAND_PORT}${NC}"
        echo ""
    else
        echo -e "  ${GREEN}---> Existing config.json found. Keeping current settings.${NC}"
    fi

    setup_systemd
    echo -e "  ${GREEN}---> Core daemon installed and running!${NC}"
}

# ──────────────────────────────────────────────────
# Option 3: Server Optimization
# ──────────────────────────────────────────────────
server_optimize() {
    check_root
    echo ""
    echo -e "  ${YELLOW}---> Applying Server Optimizations & TCP BBR...${NC}"

    if [ -f "${SYSCTL_FILE}" ]; then
        cp "${SYSCTL_FILE}" "${SYSCTL_FILE}.bak.$(date +%s)"
        echo -e "  ${YELLOW}---> Backed up existing sysctl config.${NC}"
    fi

    cat > "${SYSCTL_FILE}" <<'EOF'
# HESAR Server Optimization
fs.file-max = 1048576
fs.nr_open = 1048576
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.ip_local_port_range = 1024 65535
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.core.netdev_max_backlog = 65535
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF

    sysctl --system >/dev/null 2>&1 || true

    echo ""
    if sysctl net.ipv4.tcp_congestion_control 2>/dev/null | grep -q bbr; then
        echo -e "  ${GREEN}TCP BBR Congestion Control: ACTIVE${NC}"
    else
        echo -e "  ${YELLOW}TCP BBR might not be available on this kernel.${NC}"
    fi
    echo -e "  ${GREEN}Server Network Optimization Applied!${NC}"
}

# ──────────────────────────────────────────────────
# Update HESAR
# ──────────────────────────────────────────────────
do_update() {
    check_root
    echo ""

    if [ ! -f "${INSTALL_DIR}/hesar" ]; then
        echo -e "  ${RED}[ERROR] HESAR is not installed. Use Quick Start first.${NC}"
        return 1
    fi

    local current_version=""
    current_version=$("${INSTALL_DIR}/hesar" -version 2>/dev/null | grep -oP 'v[0-9]+\.[0-9]+\.[0-9]+' | head -1) || true
    if [ -z "$current_version" ]; then
        current_version="unknown"
    fi
    echo -e "  ${CYAN}Current version :${WHITE}${BOLD} ${current_version}${NC}"

    echo -e "  ${YELLOW}---> Checking for updates...${NC}"

    local latest_tag=""
    latest_tag=$(curl -fsSL --max-time 15 "https://api.github.com/repos/Meytiz/HESAR/releases/latest" 2>/dev/null | grep '"tag_name"' | head -1 | sed -E 's/.*"tag_name":\s*"([^"]+)".*/\1/') || true

    if [ -z "$latest_tag" ]; then
        echo -e "  ${RED}Could not check GitHub. Will try direct download.${NC}"
        latest_tag="latest"
    else
        echo -e "  ${GREEN}Latest version  :${WHITE}${BOLD} ${latest_tag}${NC}"

        if [ "$current_version" = "$latest_tag" ]; then
            echo ""
            echo -e "  ${GREEN}Already running the latest version!${NC}"
            echo ""
            read -rp "  Force reinstall anyway? [y/N]: " FORCE
            if [[ ! "$FORCE" =~ ^[Yy]$ ]]; then
                return 0
            fi
        else
            echo ""
            echo -e "  ${YELLOW}Update available: ${current_version} -> ${latest_tag}${NC}"
            echo ""
            read -rp "  Proceed with update? [Y/n]: " CONFIRM
            if [[ "$CONFIRM" =~ ^[Nn]$ ]]; then
                echo -e "  ${YELLOW}---> Update cancelled.${NC}"
                return 0
            fi
        fi
    fi

    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64)        BIN_ARCH="amd64" ;;
        aarch64|arm64) BIN_ARCH="arm64" ;;
        *) echo -e "  ${RED}[ERROR] Unsupported arch: $ARCH${NC}"; return 1 ;;
    esac

    echo ""
    echo -e "  ${YELLOW}---> Backing up current binary...${NC}"
    cp "${INSTALL_DIR}/hesar" "${INSTALL_DIR}/hesar.bak" 2>/dev/null || true
    echo -e "  ${GREEN}---> Backup saved -> ${INSTALL_DIR}/hesar.bak${NC}"

    if [ -f "${DATA_DIR}/config.json" ]; then
        cp "${DATA_DIR}/config.json" "${DATA_DIR}/config.json.bak" 2>/dev/null || true
    fi

    echo -e "  ${YELLOW}---> Stopping HESAR service...${NC}"
    systemctl stop hesar 2>/dev/null || true
    sleep 2

    echo -e "  ${YELLOW}---> Downloading new version (may take a while)...${NC}"
    local download_url="${REPO_URL}/releases/latest/download/hesar-linux-${BIN_ARCH}"
    local checksum_url="${REPO_URL}/releases/latest/download/checksums-sha256.txt"
    if [ "$latest_tag" != "latest" ]; then
        download_url="${REPO_URL}/releases/download/${latest_tag}/hesar-linux-${BIN_ARCH}"
        checksum_url="${REPO_URL}/releases/download/${latest_tag}/checksums-sha256.txt"
    fi

    local tmp_bin="/tmp/hesar-linux-${BIN_ARCH}"
    local max_retries=5
    local retry=0
    local download_ok=false

    while [ $retry -lt $max_retries ]; do
        retry=$((retry + 1))
        echo -e "  ${YELLOW}---> Download attempt ${retry}/${max_retries}...${NC}"

        if curl -fSL -C - --max-time 300 --retry 3 --retry-delay 5 -o "${tmp_bin}" "${download_url}"; then
            download_ok=true
            break
        else
            echo -e "  ${YELLOW}---> Attempt ${retry} failed. Waiting 5 seconds...${NC}"
            sleep 5
        fi
    done

    if [ "$download_ok" = false ]; then
        echo -e "  ${RED}[ERROR] Download failed after ${max_retries} attempts!${NC}"
        rm -f "${tmp_bin}"
        echo -e "  ${YELLOW}---> Restoring backup and restarting...${NC}"
        cp "${INSTALL_DIR}/hesar.bak" "${INSTALL_DIR}/hesar" 2>/dev/null || true
        systemctl start hesar 2>/dev/null || true
        echo -e "  ${RED}---> Update failed. Previous version restored.${NC}"
        return 1
    fi

    local file_size
    file_size=$(stat -c%s "${tmp_bin}" 2>/dev/null || stat -f%z "${tmp_bin}" 2>/dev/null || echo "0")
    if [ "$file_size" -lt 5000000 ]; then
        echo -e "  ${RED}[ERROR] Downloaded file too small (${file_size} bytes). Possibly corrupted.${NC}"
        rm -f "${tmp_bin}"
        cp "${INSTALL_DIR}/hesar.bak" "${INSTALL_DIR}/hesar" 2>/dev/null || true
        systemctl start hesar 2>/dev/null || true
        echo -e "  ${RED}---> Update failed. Previous version restored.${NC}"
        return 1
    fi

    if ! verify_checksum "${tmp_bin}" "${BIN_ARCH}" "${checksum_url}"; then
        echo -e "  ${RED}[ERROR] Checksum verification failed. Aborting update.${NC}"
        rm -f "${tmp_bin}"
        cp "${INSTALL_DIR}/hesar.bak" "${INSTALL_DIR}/hesar" 2>/dev/null || true
        systemctl start hesar 2>/dev/null || true
        echo -e "  ${RED}---> Update aborted. Previous version restored.${NC}"
        return 1
    fi

    echo -e "  ${YELLOW}---> Installing new binary...${NC}"
    rm -f "${INSTALL_DIR}/hesar"
    mv "${tmp_bin}" "${INSTALL_DIR}/hesar"
    chmod +x "${INSTALL_DIR}/hesar"
    chown "${HESAR_USER}:${HESAR_USER}" "${INSTALL_DIR}/hesar" 2>/dev/null || true
    echo -e "  ${GREEN}---> New binary installed (${file_size} bytes).${NC}"

    if [ ! -f "${DATA_DIR}/config.json" ] && [ -f "${DATA_DIR}/config.json.bak" ]; then
        echo -e "  ${YELLOW}---> Restoring config from backup...${NC}"
        cp "${DATA_DIR}/config.json.bak" "${DATA_DIR}/config.json"
    fi

    chmod 600 "${DATA_DIR}/config.json" 2>/dev/null || true
    chown -R "${HESAR_USER}:${HESAR_USER}" "${CONFIG_DIR}" 2>/dev/null || true

    echo -e "  ${YELLOW}---> Restarting HESAR service...${NC}"
    systemctl daemon-reload
    systemctl restart hesar
    sleep 3

    local check_count=0
    while [ $check_count -lt 3 ]; do
        if systemctl is-active --quiet hesar; then
            break
        fi
        check_count=$((check_count + 1))
        echo -e "  ${YELLOW}---> Waiting for service to start (${check_count}/3)...${NC}"
        sleep 3
        systemctl restart hesar 2>/dev/null || true
        sleep 2
    done

    if systemctl is-active --quiet hesar; then
        local new_version=""
        new_version=$("${INSTALL_DIR}/hesar" -version 2>/dev/null | grep -oP 'v[0-9]+\.[0-9]+\.[0-9]+' | head -1) || true
        echo ""
        echo -e "  ${GREEN}${BOLD}══════════════════════════════════════════════${NC}"
        echo -e "  ${GREEN}${BOLD}   HESAR UPDATED SUCCESSFULLY${NC}"
        echo -e "  ${GREEN}${BOLD}══════════════════════════════════════════════${NC}"
        echo ""
        echo -e "  ${CYAN}Previous version :${WHITE} ${current_version}${NC}"
        echo -e "  ${CYAN}New version      :${WHITE}${BOLD} ${new_version}${NC}"
        echo -e "  ${CYAN}Configuration    :${GREEN} Preserved${NC}"
        echo -e "  ${CYAN}Tunnels          :${GREEN} Preserved${NC}"
        echo ""
    else
        echo ""
        echo -e "  ${RED}[ERROR] Service failed to start after update!${NC}"
        echo -e "  ${YELLOW}---> Checking logs...${NC}"
        journalctl -u hesar --no-pager -n 10 2>/dev/null || true
        echo ""
        echo -e "  ${YELLOW}---> Restoring previous binary...${NC}"
        systemctl stop hesar 2>/dev/null || true
        cp "${INSTALL_DIR}/hesar.bak" "${INSTALL_DIR}/hesar" 2>/dev/null || true
        chmod +x "${INSTALL_DIR}/hesar"
        systemctl restart hesar 2>/dev/null || true
        echo -e "  ${YELLOW}---> Previous version restored.${NC}"
        echo -e "  ${YELLOW}---> Check logs: journalctl -u hesar -n 20${NC}"
        return 1
    fi

    rm -f "${DATA_DIR}/config.json.bak" 2>/dev/null || true
}

# ──────────────────────────────────────────────────
# Check Version
# ──────────────────────────────────────────────────
do_check_update() {
    echo ""

    local current_version=""
    if [ -f "${INSTALL_DIR}/hesar" ]; then
        current_version=$("${INSTALL_DIR}/hesar" -version 2>/dev/null | grep -oP 'v[0-9]+\.[0-9]+\.[0-9]+' | head -1) || true
    fi
    if [ -z "$current_version" ]; then
        current_version="not installed"
    fi
    echo -e "  ${CYAN}Installed version :${WHITE} ${current_version}${NC}"

    echo -e "  ${YELLOW}---> Checking GitHub...${NC}"
    local latest_tag=""
    latest_tag=$(curl -fsSL --max-time 10 "https://api.github.com/repos/Meytiz/HESAR/releases/latest" 2>/dev/null | grep '"tag_name"' | head -1 | sed -E 's/.*"tag_name":\s*"([^"]+)".*/\1/') || true

    if [ -z "$latest_tag" ]; then
        echo -e "  ${RED}Could not check for updates.${NC}"
        return 1
    fi

    echo -e "  ${CYAN}Latest version    :${WHITE}${BOLD} ${latest_tag}${NC}"

    if [ "$current_version" = "$latest_tag" ]; then
        echo -e "  ${GREEN}You are up to date!${NC}"
    else
        echo -e "  ${YELLOW}Update available!${NC}"
    fi
}

# ──────────────────────────────────────────────────
# Option 4: Uninstall
# ──────────────────────────────────────────────────
uninstall_hesar() {
    check_root
    echo ""
    echo -e "  ${RED}---> HESAR Complete Uninstallation${NC}"
    echo ""
    read -rp "  Are you sure you want to remove HESAR completely? [y/N]: " CONFIRM
    if [[ ! "$CONFIRM" =~ ^[Yy]$ ]]; then
        echo -e "  ${YELLOW}---> Uninstall aborted.${NC}"
        return
    fi

    echo -e "  ${YELLOW}---> Stopping services...${NC}"
    systemctl stop hesar 2>/dev/null || true
    systemctl disable hesar 2>/dev/null || true
    rm -f "${SYSTEMD_FILE}"
    systemctl daemon-reload 2>/dev/null || true

    echo -e "  ${YELLOW}---> Removing files...${NC}"
    rm -rf "${CONFIG_DIR}"
    rm -f "${INSTALL_DIR}/hesar"
    rm -f "${LOG_FILE}" "${LOG_FILE}".*.bak*
    rm -f "${SYSCTL_FILE}" "${SYSCTL_FILE}".bak*

    if id -u "${HESAR_USER}" >/dev/null 2>&1; then
        userdel "${HESAR_USER}" 2>/dev/null || true
    fi

    echo -e "  ${GREEN}---> HESAR uninstalled successfully!${NC}"
}

# ──────────────────────────────────────────────────
# Option 5: Status
# ──────────────────────────────────────────────────
do_status() {
    echo ""
    systemctl status hesar --no-pager -l 2>/dev/null || echo -e "  ${RED}Service not installed.${NC}"
}

# ──────────────────────────────────────────────────
# Option 6: View Logs
# ──────────────────────────────────────────────────
do_logs() {
    echo ""
    echo -e "  ${WHITE}${BOLD}-- Last 50 Log Lines --${NC}"
    echo ""
    journalctl -u hesar --no-pager -n 50 2>/dev/null \
        || tail -50 "${LOG_FILE}" 2>/dev/null \
        || echo -e "  ${RED}No logs found.${NC}"
}

# ──────────────────────────────────────────────────
# Main Menu
# ──────────────────────────────────────────────────
main_menu() {
    while true; do
        draw_banner

        echo -e "  ${WHITE}┌─${BOLD} Main Menu ${NC}${WHITE}─────────────────────────────────────────┐${NC}"
        echo -e "  ${WHITE}${NC}   ${GREEN}1)${NC}  ${GREEN}Quick Start Installation (Core + GUI Panel)${NC}  ${WHITE}${NC}"
        echo -e "  ${WHITE}${NC}   ${GREEN}2)${NC}  ${WHITE}Core Only Installation (Standalone Daemon)${NC}   ${WHITE}${NC}"
        echo -e "  ${WHITE}${NC}   ${PURPLE}3)${NC}  ${PURPLE}Update HESAR to Latest Version${NC}                ${WHITE}${NC}"
        echo -e "  ${WHITE}${NC}   ${CYAN}4)${NC}  ${WHITE}Check for Updates${NC}                             ${WHITE}${NC}"
        echo -e "  ${WHITE}${NC}   ${YELLOW}5)${NC}  ${YELLOW}Server Optimization & TCP BBR${NC}              ${WHITE}${NC}"
        echo -e "  ${WHITE}${NC}   ${CYAN}6)${NC}  ${WHITE}Check Service Status${NC}                         ${WHITE}${NC}"
        echo -e "  ${WHITE}${NC}   ${CYAN}7)${NC}  ${WHITE}View Service Logs${NC}                            ${WHITE}${NC}"
        echo -e "  ${WHITE}${NC}   ${RED}8)${NC}  ${RED}Complete Uninstall HESAR${NC}                     ${WHITE}${NC}"
        echo -e "  ${WHITE}${NC}   ${RED}0)${NC}  ${WHITE}Exit${NC}                                         ${WHITE}${NC}"
        echo -e "  ${WHITE}└─────────────────────────────────────────────────────┘${NC}"
        echo ""
        read -rp "  Option: " choice

        case "$choice" in
            1) quick_start_install; press_enter ;;
            2) core_only_install;   press_enter ;;
            3) do_update;           press_enter ;;
            4) do_check_update;     press_enter ;;
            5) server_optimize;     press_enter ;;
            6) do_status;           press_enter ;;
            7) do_logs;             press_enter ;;
            8) uninstall_hesar;     press_enter ;;
            0) echo -e "  ${GREEN}Goodbye!${NC}"; echo ""; exit 0 ;;
            *) echo -e "  ${RED}[ERROR] Invalid selection.${NC}"; sleep 1 ;;
        esac
    done
}

# ──────────────────────────────────────────────────
# CLI Arguments
# ──────────────────────────────────────────────────
case "${1:-}" in
    --quickstart)  quick_start_install ;;
    --core)        core_only_install ;;
    --update)      do_update ;;
    --check)       do_check_update ;;
    --optimize)    server_optimize ;;
    --uninstall)   uninstall_hesar ;;
    --status)      do_status ;;
    --logs)        do_logs ;;
    --verify-self) verify_self "${2:-$0}" ;;
    "")            main_menu ;;
    *)
        echo "Usage: $0 [--quickstart | --core | --update | --check | --optimize | --uninstall | --status | --logs | --verify-self <path>]"
        exit 1
        ;;
esac