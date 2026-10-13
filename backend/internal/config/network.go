package config

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

const MaxPortsPerTunnel = 64

var interfaceName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,14}$`)

func privateIPv4(raw string) bool {
	ip := net.ParseIP(raw)
	return ip != nil && ip.To4() != nil && ip.IsPrivate()
}

// ParsePorts rejects oversized ranges before allocating or binding sockets.
func ParsePorts(raw string) ([]int, error) {
	seen := make(map[int]bool)
	var ports []int
	for _, part := range strings.Split(strings.TrimSpace(raw), ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		r := strings.Split(part, "-")
		if len(r) > 2 {
			return nil, fmt.Errorf("invalid port range: %s", part)
		}
		start, err := strconv.Atoi(strings.TrimSpace(r[0]))
		if err != nil {
			return nil, fmt.Errorf("invalid port: %s", part)
		}
		end := start
		if len(r) == 2 {
			end, err = strconv.Atoi(strings.TrimSpace(r[1]))
			if err != nil {
				return nil, fmt.Errorf("invalid port range: %s", part)
			}
		}
		if start < 1 || end > 65535 || start > end {
			return nil, fmt.Errorf("invalid port range: %s", part)
		}
		if end-start+1 > MaxPortsPerTunnel {
			return nil, fmt.Errorf("too many ports: maximum %d", MaxPortsPerTunnel)
		}
		for p := start; p <= end; p++ {
			if !seen[p] {
				if len(ports) >= MaxPortsPerTunnel {
					return nil, fmt.Errorf("too many ports: maximum %d", MaxPortsPerTunnel)
				}
				seen[p] = true
				ports = append(ports, p)
			}
		}
	}
	if len(ports) == 0 {
		return nil, fmt.Errorf("port configuration is empty")
	}
	return ports, nil
}

func validHost(host string) bool {
	if net.ParseIP(host) != nil {
		return true
	}
	if len(host) == 0 || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(strings.TrimSuffix(host, "."), ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

func validateNetworkOptions(t *TunnelConfig) error {
	if err := validateCarrier(t); err != nil {
		return err
	}
	if len(t.TLSCertPEM) > 65536 || len(t.TLSKeyPEM) > 32768 || len(t.TLSCAPEM) > 65536 {
		return fmt.Errorf("TLS PEM is too large")
	}
	if t.UnderlayInterface != "" {
		if !interfaceName.MatchString(t.UnderlayInterface) {
			return fmt.Errorf("invalid underlay_interface (maximum 15 ASCII characters)")
		}
		if t.Protocol != "tcp" && t.Protocol != "quic" && t.Protocol != "kcp" {
			return fmt.Errorf("L3 underlay supports encrypted tcp, quic or kcp")
		}
		if t.ProxyURL != "" {
			return fmt.Errorf("L3 underlay cannot be combined with a SOCKS5 bypass")
		}
		if t.Mode == "iran" && !privateIPv4(t.RemoteIP) {
			return fmt.Errorf("L3 remote_ip must be the peer's private IPv4 tunnel address")
		}
		if t.Mode == "overseas" && !privateIPv4(t.ListenAddress) {
			return fmt.Errorf("L3 overseas listener must bind its private IPv4 tunnel address")
		}
	}
	if (t.NetworkProfile == "l3-gre" || t.NetworkProfile == "l3-ipip") && t.UnderlayInterface == "" && t.Carrier == "" {
		return fmt.Errorf("L3 profile requires an existing underlay_interface")
	}
	if len(t.Name) > 128 || len(t.EncryptionKey) > 1024 {
		return fmt.Errorf("name or encryption_key is too long")
	}
	if t.ListenAddress != "" && net.ParseIP(t.ListenAddress) == nil {
		return fmt.Errorf("listen_address must be a literal IP address")
	}
	if t.Mode == "iran" {
		if _, err := ParsePorts(t.LocalPorts); err != nil {
			return err
		}
		if !validHost(t.RemoteIP) {
			return fmt.Errorf("remote_ip must be an IP or hostname without a port")
		}
	}
	if t.TargetHost != "" && !validHost(t.TargetHost) {
		return fmt.Errorf("invalid target_host")
	}
	if t.QUICEnableUDP {
		return fmt.Errorf("QUIC UDP application relay is disabled pending flow redesign")
	}
	if t.DialTimeoutSeconds != 0 && (t.DialTimeoutSeconds < 1 || t.DialTimeoutSeconds > 60) {
		return fmt.Errorf("dial_timeout_seconds must be 1-60, or 0 for default")
	}
	if t.IdleTimeoutSeconds != 0 && (t.IdleTimeoutSeconds < 10 || t.IdleTimeoutSeconds > 86400) {
		return fmt.Errorf("idle_timeout_seconds must be 10-86400, or 0 for default")
	}
	if t.FallbackCooldownSeconds != 0 && (t.FallbackCooldownSeconds < 5 || t.FallbackCooldownSeconds > 3600) {
		return fmt.Errorf("fallback_cooldown_seconds must be 5-3600, or 0 for default")
	}
	if t.TLSFragmentSize != 0 && (t.TLSFragmentSize < 32 || t.TLSFragmentSize > 1024) {
		return fmt.Errorf("tls_fragment_size must be 32-1024, or 0 to disable")
	}
	if t.TLSFragmentDelayMS < 0 || t.TLSFragmentDelayMS > 25 {
		return fmt.Errorf("tls_fragment_delay_ms must be 0-25")
	}
	if t.Protocol == "wss" || t.Protocol == "wss-shaped" || t.Protocol == "auto" {
		if t.Mode == "iran" && !validHost(t.ServerName) {
			return fmt.Errorf("server_name is required for verified WSS TLS")
		}
		if t.Mode == "overseas" && (t.TLSCertFile == "" || t.TLSKeyFile == "") && (t.TLSCertPEM == "" || t.TLSKeyPEM == "") {
			return fmt.Errorf("tls_cert_file and tls_key_file are required for WSS/auto listeners")
		}
		if t.WSPath != "" {
			u, err := url.ParseRequestURI(t.WSPath)
			if err != nil || !strings.HasPrefix(t.WSPath, "/") || strings.HasPrefix(t.WSPath, "//") || u.RawQuery != "" || u.Fragment != "" || len(t.WSPath) > 256 {
				return fmt.Errorf("ws_path must be an absolute path without query or fragment")
			}
		}
	} else if t.TLSFragmentSize != 0 || t.TLSFragmentDelayMS != 0 {
		return fmt.Errorf("TLS fragmentation requires wss or auto")
	}
	if t.ProxyURL != "" {
		if t.Mode != "iran" || (t.Protocol != "tcp" && t.Protocol != "wss" && t.Protocol != "wss-shaped" && t.Protocol != "auto") {
			return fmt.Errorf("SOCKS5 proxy requires iran mode with tcp, wss or auto")
		}
		u, err := url.Parse(t.ProxyURL)
		if err != nil || u.Scheme != "socks5" || u.Hostname() == "" || u.Port() == "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
			return fmt.Errorf("proxy_url must be socks5://[user:password@]host:port")
		}
		port, err := strconv.Atoi(u.Port())
		if err != nil || port < 1 || port > 65535 {
			return fmt.Errorf("invalid SOCKS5 port")
		}
		if u.User != nil {
			password, _ := u.User.Password()
			if len(u.User.Username()) > 255 || len(password) > 255 {
				return fmt.Errorf("SOCKS5 credentials are too long")
			}
		}
	}
	switch t.NetworkProfile {
	case "", "custom", "balanced", "tcp-only", "tls-fragment", "udp-lossy", "sidecar", "raw-packet", "l3-gre", "l3-ipip", "xray", "hysteria", "shaped-wss":
	default:
		return fmt.Errorf("unknown network_profile")
	}
	return nil
}

type NetworkProfile struct {
	ID                string `json:"id"`
	Name              string `json:"name"`
	Description       string `json:"description"`
	Protocol          string `json:"protocol"`
	FragmentSize      int    `json:"tls_fragment_size"`
	FragmentDelayMS   int    `json:"tls_fragment_delay_ms"`
	DisablePMTU       bool   `json:"quic_disable_pmtu"`
	ProxyURL          string `json:"proxy_url"`
	UnderlayInterface string `json:"underlay_interface"`
	Carrier           string `json:"carrier"`
}

// Presets are starting points to measure on the actual path, not claims
// about which operator is blocked or which method is universally best.
func NetworkProfiles() []NetworkProfile {
	return []NetworkProfile{
		{ID: "balanced", Name: "Adaptive QUIC / HTTPS", Description: "Try authenticated QUIC, then verified WSS; requires TLS certificate on exit.", Protocol: "auto"},
		{ID: "tcp-only", Name: "TCP-only / UDP blocked", Description: "Verified HTTPS WebSocket on TCP; no UDP dependency.", Protocol: "wss"},
		{ID: "tls-fragment", Name: "TLS record fragmentation (experimental)", Description: "Split initial ClientHello across TLS records; measure both latency and reliability.", Protocol: "wss", FragmentSize: 128, FragmentDelayMS: 5},
		{ID: "udp-lossy", Name: "UDP available / conservative MTU", Description: "Native QUIC at 1200-byte initial size with PMTU discovery disabled; not HTTP/3 camouflage.", Protocol: "quic", DisablePMTU: true},
		{ID: "raw-packet", Name: "Managed Paqet / raw TCP", Description: "The panel provisions the packaged Paqet core and discovers the WAN route/MAC.", Protocol: "tcp", Carrier: "paqet"},
		{ID: "xray", Name: "Managed XHTTP + REALITY", Description: "The panel provisions the packaged Xray core with a restricted localhost destination.", Protocol: "tcp", Carrier: "xray"},
		{ID: "hysteria", Name: "Managed Hysteria / Salamander", Description: "The panel provisions the packaged Hysteria core; requires UDP and matching TLS credentials.", Protocol: "tcp", Carrier: "hysteria"},
		{ID: "l3-gre", Name: "Managed GRE / QUIC", Description: "Start creates an isolated GRE link and private policy route. TCP/KCP also supported.", Protocol: "quic", DisablePMTU: true, Carrier: "gre"},
		{ID: "l3-ipip", Name: "Managed IPIP / QUIC", Description: "Start creates an isolated IPv4-in-IPv4 link. Bidirectional reachability required.", Protocol: "quic", DisablePMTU: true, Carrier: "ipip"},
		{ID: "shaped-wss", Name: "Shaped WSS (experimental)", Description: "Verified TLS, authenticated data and bounded length padding; measure overhead and path behavior.", Protocol: "wss-shaped"},
	}
}
