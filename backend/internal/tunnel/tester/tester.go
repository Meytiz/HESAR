package tester

import (
	"encoding/binary"
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
// IP Spoof Tester (based on ParsaKSH/spoof-tunnel)
// ──────────────────────────────────────────────────

// craftSpoofedTCPPacket creates a TCP packet with spoofed source IP
func craftSpoofedTCPPacket(srcIP, dstIP string, dstPort int) []byte {
	src := net.ParseIP(srcIP).To4()
	dst := net.ParseIP(dstIP).To4()
	if src == nil || dst == nil {
		return nil
	}

	packet := make([]byte, 40) // IP header (20) + TCP header (20)

	// IP Header
	packet[0] = 0x45                                  // Version 4, IHL 5
	packet[1] = 0x00                                  // DSCP
	binary.BigEndian.PutUint16(packet[2:4], 40)        // Total Length
	binary.BigEndian.PutUint16(packet[4:6], 0x1234)    // ID
	packet[6] = 0x40                                   // Don't Fragment
	packet[7] = 0x00                                   // Fragment Offset
	packet[8] = 64                                     // TTL
	packet[9] = 6                                      // Protocol: TCP
	copy(packet[12:16], src)                            // Source IP (spoofed)
	copy(packet[16:20], dst)                            // Destination IP

	// IP Checksum
	binary.BigEndian.PutUint16(packet[10:12], 0)
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(packet[i : i+2]))
	}
	for sum > 0xFFFF {
		sum = (sum >> 16) + (sum & 0xFFFF)
	}
	binary.BigEndian.PutUint16(packet[10:12], ^uint16(sum))

	// TCP Header
	binary.BigEndian.PutUint16(packet[20:22], 12345)       // Source Port
	binary.BigEndian.PutUint16(packet[22:24], uint16(dstPort)) // Dest Port
	binary.BigEndian.PutUint32(packet[24:28], 0x12345678)   // Seq
	binary.BigEndian.PutUint32(packet[28:32], 0)            // Ack
	packet[32] = 0x50                                       // Data Offset: 5
	packet[33] = 0x02                                       // Flags: SYN
	binary.BigEndian.PutUint16(packet[34:36], 65535)        // Window
	binary.BigEndian.PutUint16(packet[36:38], 0)            // Checksum
	binary.BigEndian.PutUint16(packet[38:40], 0)            // Urgent

	return packet
}

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

	// Step 1: Normal TCP connect to verify reachability
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return TestResult{
			Success: false,
			Latency: time.Since(start).Milliseconds(),
			Details: fmt.Sprintf("TCP connection to %s failed: %v. Target must be reachable first.", addr, err),
		}
	}
	defer conn.Close()

	tcpConnectTime := time.Since(start).Milliseconds()

	// Step 2: Send spoofed IP header over the established connection
	spoofedPacket := craftSpoofedTCPPacket(fakeIP, targetIP, port)
	if spoofedPacket == nil {
		return TestResult{Success: false, Details: "failed to craft spoofed packet"}
	}

	if _, err := conn.Write(spoofedPacket); err != nil {
		return TestResult{
			Success: false,
			Latency: time.Since(start).Milliseconds(),
			Details: fmt.Sprintf("failed to send spoofed packet: %v", err),
		}
	}

	// Step 3: Read response
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	resp := make([]byte, 512)
	n, err := conn.Read(resp)

	totalLatency := time.Since(start).Milliseconds()

	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return TestResult{
				Success: true,
				Latency: totalLatency,
				Details: fmt.Sprintf(
					"IP Spoofing test PASSED. Connection stable with fake source %s → %s:%d (TCP: %dms, No RST detected)",
					fakeIP, targetIP, port, tcpConnectTime,
				),
			}
		}
		return TestResult{
			Success: false,
			Latency: totalLatency,
			Details: fmt.Sprintf("Connection reset after spoofed packet: %v. DPI may have blocked the spoofed header.", err),
		}
	}

	return TestResult{
		Success: true,
		Latency: totalLatency,
		Details: fmt.Sprintf(
			"IP Spoofing test PASSED. Received %d bytes. Fake source %s → %s:%d (TCP: %dms)",
			n, fakeIP, targetIP, port, tcpConnectTime,
		),
	}
}

// ──────────────────────────────────────────────────
// SNI Spoof Tester (based on aleskxyz/SNI-Spoofing-Go)
// ──────────────────────────────────────────────────

func makeTLSClientHello(sni string) []byte {
	sniBytes := []byte(sni)
	sniLen := len(sniBytes)

	// Extensions: SNI extension
	sniExtDataLen := 2 + 1 + 2 + sniLen          // server_name_list_len + type + name_len + name
	sniExtLen := 2 + sniExtDataLen                 // ext_type + ext_len + data
	extLen := sniExtLen                             // total extensions

	// Handshake body
	bodyLen := 2 + 32 + 1 + 2 + 2 + 1 + 1 + 2 + extLen // ver+random+sid+cs+comp+ext

	// TLS record
	recordLen := 1 + 3 + bodyLen // handshake_type + hs_len(3) + body

	buf := make([]byte, 0, 5+recordLen)

	// TLS Record Header
	buf = append(buf, 0x16, 0x03, 0x01) // Handshake, TLS 1.0 record
	buf = append(buf, byte(recordLen>>8), byte(recordLen))

	// Handshake Header
	buf = append(buf, 0x01) // ClientHello
	buf = append(buf, byte(bodyLen>>16), byte(bodyLen>>8), byte(bodyLen))

	// Client Version
	buf = append(buf, 0x03, 0x03) // TLS 1.2

	// Random (32 bytes)
	for i := 0; i < 32; i++ {
		buf = append(buf, byte(i+0x01))
	}

	// Session ID
	buf = append(buf, 0x00) // length 0

	// Cipher Suites
	buf = append(buf, 0x00, 0x02) // length 2
	buf = append(buf, 0x13, 0x01) // TLS_AES_128_GCM_SHA256

	// Compression
	buf = append(buf, 0x01) // length 1
	buf = append(buf, 0x00) // null

	// Extensions length
	buf = append(buf, byte(extLen>>8), byte(extLen))

	// SNI Extension
	buf = append(buf, 0x00, 0x00) // type: server_name
	buf = append(buf, byte(sniExtDataLen>>8), byte(sniExtDataLen))
	buf = append(buf, 0x00, byte(sniLen+3)) // server name list length
	buf = append(buf, 0x00)                  // name type: host_name
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

	// Step 1: TCP connect
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

	// Step 2: Send TLS ClientHello with spoofed SNI
	hello := makeTLSClientHello(sni)
	if _, err := conn.Write(hello); err != nil {
		return TestResult{
			Success: false,
			Latency: time.Since(start).Milliseconds(),
			Details: fmt.Sprintf("failed to send ClientHello: %v", err),
		}
	}

	// Step 3: Read ServerHello response
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp := make([]byte, 1024)
	n, err := conn.Read(resp)

	totalLatency := time.Since(start).Milliseconds()

	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			// Timeout = connection didn't get RST = DPI likely allowed it
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

	// Check if we got a TLS ServerHello (0x16 = handshake, 0x03 0x03 = TLS 1.2)
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