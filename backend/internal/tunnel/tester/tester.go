// Package tester contains the connectivity/protocol probes exposed through
// the panel's "Tester" page.
//
// vNext rewrite — the old package shipped two misleading probes:
//
//   - RunSNISpoofTest claimed to verify SNI spoofing but only measured
//     whether some bytes came back after a fake ClientHello (any response,
//     or even a read TIMEOUT, was reported as PASSED — a textbook false
//     positive). The SNI Spoof feature itself has been REMOVED from HESAR,
//     so its tester is removed as well.
//   - RunIPSpoofTest never spoofed anything (its own details string even
//     admitted it); it was a bare TCP connect.
//
// The replacements below test what they claim to test, with honest result
// semantics and an SSRF guard: probes refuse private/loopback/link-local
// targets (including the 169.254.169.254 cloud metadata endpoint) so the
// authenticated tester cannot be abused to scan the internal network.
package tester

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/quic-go/quic-go"
)

const (
	probeDialTimeout    = 5 * time.Second
	probeReadTimeout    = 5 * time.Second
	probeQUICTimeout    = 6 * time.Second
	maxPrivateCheckBits = 4
)

type TestResult struct {
	Success bool   `json:"success"`
	Latency int64  `json:"latency_ms"`
	Details string `json:"details"`
}

// isDisallowedTarget implements the SSRF guard shared by every probe.
func isDisallowedTarget(ip net.IP) error {
	if ip == nil {
		return fmt.Errorf("invalid target IP")
	}
	if ip.IsLoopback() {
		return fmt.Errorf("target %s is a loopback address (blocked by SSRF guard)", ip)
	}
	if ip.IsPrivate() {
		return fmt.Errorf("target %s is in a private range (blocked by SSRF guard)", ip)
	}
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return fmt.Errorf("target %s is link-local (blocked: includes cloud metadata endpoints)", ip)
	}
	if ip.IsUnspecified() || ip.IsMulticast() {
		return fmt.Errorf("target %s is not a unicast routable address", ip)
	}
	// Defense in depth: the cloud metadata IP (169.254.169.254) is already
	// covered by IsLinkLocalUnicast, but call it out explicitly.
	if ip.Equal(net.IPv4(169, 254, 169, 254)) {
		return fmt.Errorf("target %s is the cloud metadata endpoint (blocked)", ip)
	}
	return nil
}

func validateProbeTarget(targetIP string, port int) (net.IP, error) {
	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("invalid port: must be 1-65535")
	}
	ip := net.ParseIP(targetIP)
	if ip == nil {
		return nil, fmt.Errorf("invalid target IP")
	}
	if err := isDisallowedTarget(ip); err != nil {
		return nil, err
	}
	return ip, nil
}

// ──────────────────────────────────────────────────
// TCP reachability probe
// ──────────────────────────────────────────────────

// RunTCPTest performs a real TCP three-way handshake against targetIP:port.
// It tests connectivity ONLY — nothing more is claimed.
func RunTCPTest(targetIP string, port int) TestResult {
	if _, err := validateProbeTarget(targetIP, port); err != nil {
		return TestResult{Success: false, Details: err.Error()}
	}

	addr := net.JoinHostPort(targetIP, strconv.Itoa(port))
	start := time.Now()
	conn, err := net.DialTimeout("tcp", addr, probeDialTimeout)
	if err != nil {
		return TestResult{
			Success: false,
			Latency: time.Since(start).Milliseconds(),
			Details: fmt.Sprintf("TCP handshake to %s failed: %v", addr, err),
		}
	}
	_ = conn.Close()
	return TestResult{
		Success: true,
		Latency: time.Since(start).Milliseconds(),
		Details: fmt.Sprintf("TCP handshake to %s completed (reachability confirmed; no protocol verification).", addr),
	}
}

// ──────────────────────────────────────────────────
// TLS probe (real handshake, reports negotiated version)
// ──────────────────────────────────────────────────

// RunTLSTest performs an actual TLS handshake against the target and reports
// the negotiated protocol version. Certificate trust is intentionally not
// validated (this is a reachability/protocol probe, not a PKI audit).
func RunTLSTest(targetIP string, port int, serverName string) TestResult {
	if _, err := validateProbeTarget(targetIP, port); err != nil {
		return TestResult{Success: false, Details: err.Error()}
	}

	addr := net.JoinHostPort(targetIP, strconv.Itoa(port))
	start := time.Now()

	dialer := &net.Dialer{Timeout: probeDialTimeout}
	conf := &tls.Config{
		InsecureSkipVerify: true, // probe semantics — see doc comment
		ServerName:         serverName,
	}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, conf)
	if err != nil {
		return TestResult{
			Success: false,
			Latency: time.Since(start).Milliseconds(),
			Details: fmt.Sprintf("TLS handshake with %s failed: %v", addr, err),
		}
	}
	defer conn.Close()

	state := conn.ConnectionState()
	version := tlsVersionName(state.Version)
	subject := ""
	if len(state.PeerCertificates) > 0 {
		subject = state.PeerCertificates[0].Subject.String()
	}
	detail := fmt.Sprintf("TLS handshake OK with %s — negotiated %s, ALPN %q", addr, version, state.NegotiatedProtocol)
	if subject != "" {
		detail += fmt.Sprintf(", subject %q", subject)
	}
	return TestResult{
		Success: true,
		Latency: time.Since(start).Milliseconds(),
		Details: detail,
	}
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS10:
		return "TLS 1.0"
	default:
		return fmt.Sprintf("unknown(0x%04x)", v)
	}
}

// ──────────────────────────────────────────────────
// QUIC probe (real QUIC handshake attempt)
// ──────────────────────────────────────────────────

// RunQUICTest attempts a genuine QUIC handshake against the target. A
// completed handshake proves UDP + QUIC reachability. Handshake REJECTIONS
// are still useful signal (something QUIC-ish answered), while timeouts
// indicate filtering.
func RunQUICTest(targetIP string, port int) TestResult {
	if _, err := validateProbeTarget(targetIP, port); err != nil {
		return TestResult{Success: false, Details: err.Error()}
	}

	addr := net.JoinHostPort(targetIP, strconv.Itoa(port))
	start := time.Now()

	ctx, cancel := context.WithTimeout(context.Background(), probeQUICTimeout)
	defer cancel()

	conn, err := quic.DialAddr(ctx, addr, &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"hq-29", "h3", "hesar-quic/1"},
	}, &quic.Config{
		HandshakeIdleTimeout: probeQUICTimeout,
	})
	if err == nil {
		_ = conn.CloseWithError(0, "probe done")
		return TestResult{
			Success: true,
			Latency: time.Since(start).Milliseconds(),
			Details: fmt.Sprintf("QUIC handshake with %s completed — UDP path is open for QUIC/HTTP3.", addr),
		}
	}

	return TestResult{
		Success: false,
		Latency: time.Since(start).Milliseconds(),
		Details: fmt.Sprintf("QUIC handshake with %s failed: %v (timeout usually means UDP is filtered; a version/transport error means a QUIC endpoint answered).", addr, err),
	}
}
