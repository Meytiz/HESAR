package tester

import (
    "fmt"
    "net"
    "os"
    "syscall"
    "time"

    "golang.org/x/net/ipv4"
)

func checkRawSocketCapability() error {
    fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
    if err != nil {
        return fmt.Errorf("raw socket unavailable (need root/CAP_NET_RAW): %w", err)
    }
    syscall.Close(fd)
    return nil
}

func RunRealIPSpoofTest(targetIP string, port int, fakeIP string) TestResult {
    if os.Geteuid() != 0 {
        return TestResult{
            Success: false,
            Details: "root or CAP_NET_RAW required for real IP spoofing test",
        }
    }
    if err := checkRawSocketCapability(); err != nil {
        return TestResult{Success: false, Details: err.Error()}
    }

    src := net.ParseIP(fakeIP).To4()
    dst := net.ParseIP(targetIP).To4()
    if src == nil || dst == nil {
        return TestResult{Success: false, Details: "invalid IP"}
    }

    conn, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
    if err != nil {
        return TestResult{Success: false, Details: fmt.Sprintf("raw socket open failed: %v", err)}
    }
    defer conn.Close()

    rawConn, err := ipv4.NewRawConn(conn)
    if err != nil {
        return TestResult{Success: false, Details: fmt.Sprintf("raw conn init failed: %v", err)}
    }

    tcpPayload := buildTCPHeader(src, dst, port)

    header := &ipv4.Header{
        Version:  4,
        Len:      20,
        TotalLen: 20 + len(tcpPayload),
        TTL:      64,
        Protocol: 6, // TCP
        Src:      src,
        Dst:      dst,
    }

    start := time.Now()
    if err := rawConn.WriteTo(header, tcpPayload, nil); err != nil {
        return TestResult{
            Success: false,
            Latency: time.Since(start).Milliseconds(),
            Details: fmt.Sprintf("spoofed packet send failed: %v", err),
        }
    }

    return TestResult{
        Success: true,
        Latency: time.Since(start).Milliseconds(),
        Details: fmt.Sprintf(
            "Spoofed SYN sent: %s -> %s:%d. "+
                "NOTE: Response verification requires packet capture (pcap) on egress path; "+
                "success here only confirms send, not that source NAT/RPF didn't rewrite/drop it.",
            fakeIP, targetIP, port,
        ),
    }
}

func buildTCPHeader(src, dst net.IP, dstPort int) []byte {
    tcp := make([]byte, 20)
    binary.BigEndian.PutUint16(tcp[0:2], 12345)
    binary.BigEndian.PutUint16(tcp[2:4], uint16(dstPort))
    binary.BigEndian.PutUint32(tcp[4:8], 0x12345678)
    binary.BigEndian.PutUint32(tcp[8:12], 0)
    tcp[12] = 0x50
    tcp[13] = 0x02
    binary.BigEndian.PutUint16(tcp[14:16], 65535)
    binary.BigEndian.PutUint16(tcp[16:18], 0)
    binary.BigEndian.PutUint16(tcp[18:20], 0)

    checksum := tcpChecksum(src, dst, tcp)
    binary.BigEndian.PutUint16(tcp[16:18], checksum)
    return tcp
}

func tcpChecksum(src, dst net.IP, tcpHeader []byte) uint16 {
    pseudo := make([]byte, 12)
    copy(pseudo[0:4], src)
    copy(pseudo[4:8], dst)
    pseudo[8] = 0
    pseudo[9] = 6
    binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(tcpHeader)))

    data := append(pseudo, tcpHeader...)
    var sum uint32
    for i := 0; i < len(data)-1; i += 2 {
        sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
    }
    if len(data)%2 == 1 {
        sum += uint32(data[len(data)-1]) << 8
    }
    for sum > 0xFFFF {
        sum = (sum >> 16) + (sum & 0xFFFF)
    }
    return ^uint16(sum)
}