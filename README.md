<div align="center">

# 🏰 HESAR

### A Modern Reverse-Tunnel Platform for Bypassing Filtering & DPI

<p>
  <img src="https://img.shields.io/github/stars/Meytiz/HESAR?style=for-the-badge&color=gold" alt="stars">
  <img src="https://img.shields.io/github/forks/Meytiz/HESAR?style=for-the-badge&color=blue" alt="forks">
  <img src="https://img.shields.io/github/watchers/Meytiz/HESAR?style=for-the-badge&color=green" alt="watchers">
  <img src="https://img.shields.io/github/license/Meytiz/HESAR?style=for-the-badge&color=orange" alt="license">
</p>

<p>
  <img src="https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat-square&logo=go&logoColor=white" alt="Go">
  <img src="https://img.shields.io/badge/React-18-61DAFB?style=flat-square&logo=react&logoColor=black" alt="React">
  <img src="https://img.shields.io/badge/TypeScript-Vite-3178C6?style=flat-square&logo=typescript&logoColor=white" alt="TypeScript">
  <img src="https://img.shields.io/badge/TailwindCSS-latest-38B2AC?style=flat-square&logo=tailwind-css&logoColor=white" alt="TailwindCSS">
  <img src="https://img.shields.io/badge/Platform-Linux%20amd64%2Farm64-lightgrey?style=flat-square&logo=linux&logoColor=black" alt="Platform">
</p>

**HESAR** (meaning *"Fortress"* in Persian) is a modern reverse-tunnel platform specifically engineered for networks with heavy filtering and environments subject to Deep Packet Inspection (DPI).

[Quick Install](#-quick-installation) •
[Features](#-features) •
[Architecture](#️-architecture) •
[Configuration](#️-configuration) •
[Security](#-security) •
[Contributing](#-contributing)

</div>

---

## 📑 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
  - [Tunnel Protocols](#️-tunnel-protocols)
  - [Encryption](#-encryption)
  - [Web Management Panel](#️-web-management-panel)
  - [CLI Installer](#️-cli-installer)
- [Architecture](#️-architecture)
- [Quick Installation](#-quick-installation)
- [Offline Installation](#-offline-installation)
- [Build From Source](#-build-from-source)
- [Configuration](#️-configuration)
- [Security](#-security)
- [Server Optimization](#-server-optimization)
- [Project Structure](#-project-structure)
- [Troubleshooting](#-troubleshooting)
- [Roadmap](#️-roadmap)
- [Contributing](#-contributing)
- [License](#-license)

---

## 🌟 Overview

**HESAR** is a lightweight, secure, and powerful tunneling solution that lets you route network traffic from a server inside a restricted network (e.g. behind a national firewall) to a server on the open internet — without DPI systems being able to detect or block it.

The project is a combination of:

| Layer | Technology |
|---|---|
| 🐹 **Backend** | Go — a single, lightweight, self-contained binary |
| ⚛️ **Frontend (Web Panel)** | React + TypeScript + Vite + Tailwind CSS |

Shipped as a **single self-contained binary**, it provides:

| Capability | Description |
|---|---|
| 🔐 Encrypted tunnels | With AEAD framing and length-prefixed chunks |
| 🌀 Traffic obfuscation | SNI Spoofing, IP Header Obfuscation |
| 📊 Real-time dashboard | CPU/RAM, load, BBR, uptime |
| ⚙️ Auto-install & network tuning | One command, systemd service, BBR |

---

## ✨ Features

### 🛡️ Tunnel Protocols

| Protocol | Description |
|---|---|
| **TCP** | Encrypted TCP transport with AEAD framing and length-prefixed chunks |
| **KCP** | Low-latency, reliable UDP tunnel for high packet-loss environments |
| **SNI Spoofing** | Forges TLS ClientHello with a custom SNI to disguise traffic |
| **IP Header Obfuscation** | Custom packet encapsulation to resist DPI fingerprinting |

### 🔒 Encryption

HESAR uses modern cryptographic standards with **per-session key isolation**:

| Component | Purpose |
|---|---|
| **X25519** | Secure elliptic-curve key exchange |
| **ChaCha20-Poly1305** | Fast and secure AEAD encryption |
| **HKDF** | HMAC-based key derivation for session separation |
| **Random Salt** | 32-byte random salt per connection to reduce fingerprinting |

### 🎛️ Web Management Panel

The web panel is built with **React 18 + TypeScript + Vite + Tailwind CSS**:

| Feature | Description |
|---|---|
| **Dashboard** | Real-time tunnel status, CPU/RAM usage, load, BBR and uptime |
| **Tunnel Manager** | Create, edit, start, stop and delete tunnels |
| **Live Logs** | Live log streaming via WebSocket |
| **DPI Tester** | Test SNI Spoofing and IP Obfuscation |
| **Settings** | Manage username, password, log path and rotation size |
| **Key Generator** | Generate X25519 key pairs and tunnel cipher keys |
| **Responsive** | Responsive design for mobile and desktop |

### 🖥️ CLI Installer

The `scripts/hesar.sh` script provides the following commands:

| Command | Description |
|---|---|
| `--quickstart` | Auto-install with secure random configuration |
| `--core` | Install service as a daemon only |
| `--optimize` | Enable TCP BBR and kernel network tuning |
| `--uninstall` | Completely remove HESAR and related files |
| `--status` | Show systemd service status |
| `--logs` | Show latest logs |

---

## 🏗️ Architecture

```
┌────────────────────────────────┐    ┌────────────────────────────────┐
│                                │    │                                │
│        🇮🇷 BRIDGE SERVER       │    │        🌐 NODE SERVER          │
│    (Restricted Network)        │    │      (Open Internet)           │
│                                │    │                                │
│  ┌────────────────────────┐    │    │    ┌────────────────────────┐  │
│  │ Local Ports            │    │    │    │ Target Forward         │  │
│  │ :80, :443              │────┼────┼───▶│ :8080, :1080           │  │
│  └────────────────────────┘    │    │    └────────────────────────┘  │
│                                │    │                                │
│  ┌────────────────────────┐    │    │    ┌────────────────────────┐  │
│  │ HESAR Management Panel │    │    │    │ HESAR Management Panel │  │
│  │ :5123                  │    │    │    │ :5123                  │  │
│  └────────────────────────┘    │    │    └────────────────────────┘  │
│                                │    │                                │
└────────────────────────────────┘    └────────────────────────────────┘
              ▲                                   ▲
              │           Encrypted Tunnel        │
              └───────────────────────────────────┘
              TCP / KCP + ChaCha20-Poly1305 AEAD
              + SNI/IP Header Obfuscation
```

- **🛡️ Bridge Server**: Sits inside the restricted network and dials outward to the node server to bypass filtering.
- **🌐 Node Server**: Sits on the open internet and forwards incoming traffic to the final destination.

---

## ⚡ Quick Installation

> **Requirements:** Linux (amd64/arm64) with root access

Install with a **single command**:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/Meytiz/HESAR/main/scripts/hesar.sh)
```

The installer will:

- ✅ Install the `hesar` binary to `/usr/local/bin`
- ✅ Create a dedicated `hesar` system user
- ✅ Generate `/etc/hesar/data/config.json` with secure random values
- ✅ Register and start the `hesar.service` in systemd

**Sample output:**

```
======================================================================
               HESAR QUICK START SETUP SUCCESSFUL
======================================================================

  GUI Panel Address : http://SERVER_IP:5123/
  Listen Port       : 5123
  Username          : admin_8392
  Password          : Hesar#a8Kx9mN2pQ4w

======================================================================
  ⚠️  SAVE THESE CREDENTIALS — They won't be shown again!
  ⚠️  Change password after first login.
======================================================================
```

> 🔒 Credentials are randomly generated per install and never sent externally.

---

## 📦 Offline Installation

### Method 1 — Pre-built binary

1. Download the appropriate build from [Releases](https://github.com/Meytiz/HESAR/releases).
2. Transfer it to your server:

```bash
scp hesar-linux-amd64 root@SERVER_IP:/tmp/hesar
```

3. Run and install:

```bash
chmod +x /tmp/hesar
sudo /tmp/hesar
```

### Method 2 — Build manually

If you have limited internet access, build the frontend locally first, then compile the backend (see [Build From Source](#-build-from-source)).

---

## 🔨 Build From Source

### Prerequisites

| Tool | Version |
|---|---|
| **Go** | 1.22+ |
| **Node.js** | 18+ |
| **npm** | 9+ |

### Build the frontend

```bash
cd frontend
npm install
npm run build
```

### Build the backend

```bash
cd backend
rm -rf internal/api/dist
cp -r ../frontend/dist internal/api/dist

go mod download
go build \
  -ldflags="-s -w \
  -X main.Version=$(git describe --tags --always) \
  -X main.BuildDate=$(date +%Y-%m-%d)" \
  -o hesar \
  cmd/hesar/main.go
```

### Run directly

```bash
./hesar -config data/config.json
```

---

## ⚙️ Configuration

Main configuration file:

```
/etc/hesar/data/config.json
```

### Server settings

| Key | Description |
|---|---|
| `admin_username` | Web panel username |
| `admin_password` | Web panel password |
| `listen_port` | Main service and panel port |
| `log_path` | Log storage path |
| `log_max_size_mb` | Max size per log file (rotates after) |
| `secret_key` | Master service key |

### Tunnel settings

| Key | Possible values |
|---|---|
| `protocol` | `tcp` / `kcp` / `ip_spoof` / `sni_spoof` |
| `mode` | `iran` or `overseas` |
| `local_ports` | Local ports (e.g. `[80, 443]`) |
| `remote_ip` | Destination node address |
| `remote_port` | Destination node port |
| `target_port` | Final forward port |
| `spoof_sni` | Spoofed SNI for ClientHello |
| `fake_ip` | Fake IP used in encapsulation |

---

## 🔐 Security

| Layer | Implementation |
|---|---|
| 🔑 Key exchange | **X25519** elliptic curve |
| 🛡️ Traffic encryption | **ChaCha20-Poly1305** AEAD |
| 🧬 Key isolation | **HKDF** per session |
| 🎲 Random salt | 32 random bytes per connection |
| 🔓 API authentication | **JWT** for REST and WebSocket |
| 🚦 Login protection | Rate-limited + constant-time credential check |
| 👤 Dedicated user | Non-root user with systemd hardening |
| 📂 Config file permissions | Enforced `0600` |
| ✍️ Safe writes | Atomic writes for `config.json` |
| 🛑 SSRF protection | In diagnostic tools |
| ✅ Server-side validation | On all requests |

---

## 🚀 Server Optimization

To enable **TCP BBR** and tune kernel parameters:

```bash
sudo ./hesar.sh --optimize
```

This will:

- ⚙️ Tune TCP kernel parameters
- 🚀 Enable BBR if supported by the kernel
- 💾 Persist `sysctl` values in `/etc/sysctl.d/99-hesar-tune.conf`

---

## 📂 Project Structure

```
HESAR/
├── 📁 backend/                    # 🐹 Go backend
│   ├── 📁 cmd/hesar/
│   │   └── 📄 main.go             # Application entry point
│   ├── 📁 internal/
│   │   ├── 📁 api/                # HTTP API + WebSocket + embedded frontend
│   │   ├── 📁 config/             # Configuration management
│   │   ├── 📁 system/             # systemd + sysctl operations
│   │   └── 📁 tunnel/             # TCP/KCP/SNI/IP tunnel implementations
│   ├── 📄 go.mod
│   └── 📄 go.sum
│
├── 📁 frontend/                   # ⚛️ React + TypeScript UI
│   ├── 📁 src/
│   │   ├── 📁 components/         # UI components (Dashboard, Tunnels, ...)
│   │   ├── 📁 pages/              # Main pages
│   │   ├── 📁 services/           # API services
│   │   ├── 📄 App.tsx             # Application root
│   │   ├── 📄 main.tsx            # React entry point
│   │   ├── 📄 types.ts            # TypeScript definitions
│   │   └── 📄 index.css           # Global styles
│   ├── 📄 index.html
│   ├── 📄 package.json
│   ├── 📄 tailwind.config.js
│   ├── 📄 vite.config.ts
│   └── 📄 tsconfig.json
│
├── 📁 scripts/
│   └── 📄 hesar.sh                # CLI installer and manager
│
├── 📁 .github/workflows/
│   └── 📄 build.yml               # GitHub Actions CI/CD
│
├── 📄 LICENSE                     # MIT License
├── 📄 README.md                   # This file
└── 📄 .gitignore
```

---

## 🔧 Troubleshooting

| Issue | Solution |
|---|---|
| Port already in use | Change `listen_port` in `/etc/hesar/data/config.json` |
| Permission denied | `chown -R hesar:hesar /etc/hesar` |
| Web panel won't open | Open the port in your firewall: `ufw allow 5123/tcp` |
| Service won't start | Inspect logs: `journalctl -u hesar -f` |
| Tunnel won't connect | Ensure the cipher key matches on both endpoints |
| Frontend build error | `rm -rf node_modules && npm install` and retry |

---

## 🗺️ Roadmap

- 🚧 WireGuard Transport
- 🚧 QUIC Transport
- 🚧 Multi Node Clustering
- 🚧 Monitoring and Alerts
- 🚧 WebSocket Transport
- 🚧 Prometheus Metrics Exporter
- 🚧 High Availability
- 🚧 Automatic Let's Encrypt TLS

---

## 🤝 Contributing

Suggestions, bug reports and feature requests are warmly welcome! 🎉

1. 🍴 **Fork** the repository
2. 🌿 Create a feature branch (`git checkout -b feature/amazing-feature`)
3. 💾 **Commit** your changes (`git commit -m 'Add amazing feature'`)
4. 📤 **Push** the branch (`git push origin feature/amazing-feature`)
5. 🔀 Open a **Pull Request**

> ⚠️ For major changes, please open an **Issue** first to discuss what you would like to change.

---

## 📜 License

This project is licensed under the **[MIT License](https://github.com/Meytiz/HESAR/blob/main/LICENSE)**.

```
MIT License - Copyright (c) 2026 Meytiz (HESAR Project)
```

---

<div align="center">

### 🌟 If HESAR helped you bypass restrictions, consider giving it a ⭐ on GitHub — it helps the project grow!

<p>
  <a href="https://github.com/Meytiz/HESAR/stargazers"><img src="https://img.shields.io/github/stars/Meytiz/HESAR?style=social" alt="GitHub stars"></a>
  <a href="https://github.com/Meytiz/HESAR/network/members"><img src="https://img.shields.io/github/forks/Meytiz/HESAR?style=social" alt="GitHub forks"></a>
  <a href="https://github.com/Meytiz/HESAR/watchers"><img src="https://img.shields.io/github/watchers/Meytiz/HESAR?style=social" alt="GitHub watchers"></a>
</p>

**Built with ❤️ by [Meytiz](https://github.com/Meytiz)**

*Making the internet accessible for everyone*

</div>
