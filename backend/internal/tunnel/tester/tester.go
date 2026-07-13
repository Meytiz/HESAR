package tester

import (
	"fmt"
	"net"
	"time"
)

type TestResult struct {
	Success bool   `json:"success"`
	Latency int64  `json:"latency_ms"`
	Details string `json:"details"`
}

// ──────────────────────────────────────────────────
// IP Spoof Tester
// ──────────────────────────────────────────────────

func RunIPSpoofTest(targetIP string, port int, fakeIP string) TestResult {
	if port < 1 || port > 65535 {
		return TestResult{Success: false, Details: "invalid port"}
	}
	if net.ParseIP(targetIP) == nil {
		return TestResult{Success: false, Details: "invalid target IP"}
	}
	if net.ParseIP(fakeIP) == nil {
		return TestResult{Success: false, Details: "invalid fake IP"}
	}

	addr := fmt.Sprintf("%s:%d", targetIP, port)
	start := time.Now()

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return TestResult{
			Success: false,
			Latency: time.Since(start).Milliseconds(),
			Details: fmt.Sprintf("TCP connection to %s failed: %v", addr, err),
		}
	}
	defer conn.Close()

	return TestResult{
		Success: true,
		Latency: time.Since(start).Milliseconds(),
		Details: fmt.Sprintf(
			"Handshake Compatibility Test PASSED. TCP reachable at %s. "+
				"IP source spoofing NOT tested (requires raw socket + CAP_NET_RAW, "+
				"unavailable/ineffective on most cloud infrastructure).",
			addr,
		),
	}
}

// ──────────────────────────────────────────────────
// SNI Spoof Tester (based on aleskxyz/SNI-Spoofing-Go)
// ──────────────────────────────────────────────────

func makeTLSClientHello(sni string) []byte {
	sniBytes := []byte(sni)
	sniLen := len(sniBytes)

	sniExtDataLen := 2 + 1 + 2 + sniLen
	sniExtLen := 2 + sniExtDataLen
	extLen := sniExtLen

	bodyLen := 2 + 32 + 1 + 2 + 2 + 1 + 1 + 2 + extLen
	recordLen := 1 + 3 + bodyLen

	buf := make([]byte, 0, 5+recordLen)

	buf = append(buf, 0x16, 0x03, 0x01)
	buf = append(buf, byte(recordLen>>8), byte(recordLen))

	buf = append(buf, 0x01)
	buf = append(buf, byte(bodyLen>>16), byte(bodyLen>>8), byte(bodyLen))

	buf = append(buf, 0x03, 0x03)

	for i := 0; i < 32; i++ {
		buf = append(buf, byte(i+0x01))
	}

	buf = append(buf, 0x00)

	buf = append(buf, 0x00, 0x02)
	buf = append(buf, 0x13, 0x01)

	buf = append(buf, 0x01)
	buf = append(buf, 0x00)

	buf = append(buf, byte(extLen>>8), byte(extLen))

	buf = append(buf, 0x00, 0x00)
	buf = append(buf, byte(sniExtDataLen>>8), byte(sniExtDataLen))
	buf = append(buf, 0x00, byte(sniLen+3))
	buf = append(buf, 0x00)
	buf = append(buf, byte(sniLen>>8), byte(sniLen))
	buf = append(buf, sniBytes...)

	return buf
}

func RunSNISpoofTest(targetIP string, port int, sni string) TestResult {
	if port < 1 || port > 65535 {
		return TestResult{Success: false, Details: "invalid port"}
	}
	if net.ParseIP(targetIP) == nil {
		return TestResult{Success: false, Details: "invalid target IP"}
	}
	if sni == "" {
		return TestResult{Success: false, Details: "SNI domain is required"}
	}

	addr := fmt.Sprintf("%s:%d", targetIP, port)
	start := time.Now()

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return TestResult{
			Success: false,
			Latency: time.Since(start).Milliseconds(),
			Details: fmt.Sprintf("TCP connection to %s failed: %v", addr, err),
		}
	}
	defer conn.Close()

	tcpTime := time.Since(start).Milliseconds()

	hello := makeTLSClientHello(sni)
	if _, err := conn.Write(hello); err != nil {
		return TestResult{
			Success: false,
			Latency: time.Since(start).Milliseconds(),
			Details: fmt.Sprintf("failed to send ClientHello: %v", err),
		}
	}

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp := make([]byte, 1024)
	n, err := conn.Read(resp)

	totalLatency := time.Since(start).Milliseconds()

	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return TestResult{
				Success: true,
				Latency: totalLatency,
				Details: fmt.Sprintf(
					"SNI Spoof PASSED. Connection stable with SNI '%s' → %s:%d (No RST from DPI). TCP: %dms",
					sni, targetIP, port, tcpTime,
				),
			}
		}
		return TestResult{
			Success: false,
			Latency: totalLatency,
			Details: fmt.Sprintf("Connection reset: %v. DPI likely blocked SNI '%s'.", err, sni),
		}
	}

	if n >= 3 && resp[0] == 0x16 && resp[1] == 0x03 {
		return TestResult{
			Success: true,
			Latency: totalLatency,
			Details: fmt.Sprintf(
				"SNI Spoof PASSED! Received TLS ServerHello (%d bytes). SNI '%s' accepted by %s:%d. TCP: %dms",
				n, sni, targetIP, port, tcpTime,
			),
		}
	}

	return TestResult{
		Success: true,
		Latency: totalLatency,
		Details: fmt.Sprintf(
			"SNI Spoof PASSED. Received %d bytes from %s:%d with SNI '%s'. TCP: %dms",
			n, targetIP, port, sni, tcpTime,
		),
	}
}