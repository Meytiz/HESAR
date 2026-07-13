package tunnel

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/Meytiz/HESAR/backend/internal/config"
	"github.com/Meytiz/HESAR/backend/internal/system"
	"github.com/Meytiz/HESAR/backend/internal/tunnel/crypto"
)

type IPSpoofHandler struct {
	cfg       *config.TunnelConfig
	ctx       context.Context
	cancel    context.CancelFunc
	listeners []net.Listener
	mu        sync.Mutex
}

func NewIPSpoofHandler(cfg *config.TunnelConfig) *IPSpoofHandler {
	ctx, cancel := context.WithCancel(context.Background())
	return &IPSpoofHandler{cfg: cfg, ctx: ctx, cancel: cancel}
}

func CraftSpoofedIPHeader(fakeIP string) []byte {
	ip := net.ParseIP(fakeIP)
	if ip == nil {
		ip = net.ParseIP("185.10.20.30")
	}
	ip = ip.To4()

	buf := make([]byte, 24)
	buf[0] = 0x45
	buf[1] = 0x00
	binary.BigEndian.PutUint16(buf[2:4], 24)
	binary.BigEndian.PutUint16(buf[4:6], 0x5432)
	buf[6] = 0x40
	buf[7] = 0x00
	buf[8] = 0x40
	buf[9] = 0xFC
	binary.BigEndian.PutUint16(buf[10:12], 0)
	copy(buf[12:16], ip)
	copy(buf[16:20], []byte{0x08, 0x08, 0x08, 0x08})
	copy(buf[20:24], []byte{0xFE, 0xED, 0xFA, 0xCE})

	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(buf[i : i+2]))
	}
	for sum > 0xFFFF {
		sum = (sum >> 16) + (sum & 0xFFFF)
	}
	binary.BigEndian.PutUint16(buf[10:12], ^uint16(sum))

	return buf
}

func (h *IPSpoofHandler) Start() error {
	// psk authenticates the ephemeral X25519 handshake performed inside
	// crypto.NewSecureConn — never used directly as an encryption key.
	psk := sha256.Sum256([]byte(h.cfg.EncryptionKey))
	fakeIP := h.cfg.FakeIP
	if fakeIP == "" {
		fakeIP = "185.10.20.30"
	}
	if h.cfg.Mode == "iran" {
		ports, err := ParsePorts(h.cfg.LocalPorts)
		if err != nil {
			return fmt.Errorf("IP Spoof iran parse ports: %w", err)
		}
		h.mu.Lock()
		for _, port := range ports {
			l, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
			if err != nil {
				h.mu.Unlock()
				h.Stop()
				return fmt.Errorf("IP Spoof listen port %d: %w", port, err)
			}
			h.listeners = append(h.listeners, l)
			go h.runIranListener(l, psk[:], fakeIP)
		}
		h.mu.Unlock()
		system.LogInfo("IP Spoof Iran tunnel [%s] (FakeIP: %s) started on ports: %s", h.cfg.Name, fakeIP, h.cfg.LocalPorts)
	} else if h.cfg.Mode == "overseas" {
		l, err := net.Listen("tcp", fmt.Sprintf(":%d", h.cfg.RemotePort))
		if err != nil {
			return fmt.Errorf("IP Spoof overseas listen port %d: %w", h.cfg.RemotePort, err)
		}
		h.mu.Lock()
		h.listeners = append(h.listeners, l)
		h.mu.Unlock()
		go h.runOverseasListener(l, psk[:])
		system.LogInfo("IP Spoof Overseas tunnel [%s] started on port: %d", h.cfg.Name, h.cfg.RemotePort)
	} else {
		return fmt.Errorf("unknown mode: %s", h.cfg.Mode)
	}
	return nil
}

func (h *IPSpoofHandler) Stop() {
	h.cancel()
	h.mu.Lock()
	for _, l := range h.listeners {
		_ = l.Close()
	}
	h.listeners = nil
	h.mu.Unlock()
	system.LogInfo("IP Spoof tunnel [%s] stopped", h.cfg.Name)
}

func (h *IPSpoofHandler) runIranListener(l net.Listener, psk []byte, fakeIP string) {
	for {
		clientConn, err := l.Accept()
		if err != nil {
			select {
			case <-h.ctx.Done():
				return
			default:
				system.LogWarn("IP Spoof Iran accept error: %v", err)
				time.Sleep(100 * time.Millisecond)
				continue
			}
		}
		go func(c net.Conn) {
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(10 * time.Second))
			remoteAddr := fmt.Sprintf("%s:%d", h.cfg.RemoteIP, h.cfg.RemotePort)
			remoteConn, err := net.DialTimeout("tcp", remoteAddr, 10*time.Second)
			if err != nil {
				system.LogError("IP Spoof Iran connect to [%s]: %v", remoteAddr, err)
				return
			}
			defer remoteConn.Close()

			// A single deadline now covers the entire pre-proxy sequence
			// on remoteConn: spoofed-header write, ACK read, and the
			// X25519 handshake round-trip. Previously only `c` (the
			// local listener connection) had a deadline — remoteConn
			// itself had none, so a stalled overseas peer during the ACK
			// read alone could already leak this goroutine/fd; the added
			// handshake read makes this strictly worse without a fix.
			_ = remoteConn.SetDeadline(time.Now().Add(10 * time.Second))

			spoofHeader := CraftSpoofedIPHeader(fakeIP)
			if _, err := remoteConn.Write(spoofHeader); err != nil {
				system.LogError("IP Spoof Iran send header: %v", err)
				return
			}
			ack := make([]byte, 4)
			if _, err := io.ReadFull(remoteConn, ack); err != nil {
				system.LogError("IP Spoof Iran read ACK: %v", err)
				return
			}
			secureConn, err := crypto.NewSecureConn(remoteConn, psk, true)
			if err != nil {
				system.LogError("IP Spoof Iran secure handshake: %v", err)
				return
			}
			_ = remoteConn.SetDeadline(time.Time{})
			defer secureConn.Close()

			_ = c.SetDeadline(time.Time{})
			ProxyBidirectional(c, secureConn, func(in, out int64) {
				if config.GlobalConfig != nil {
					_ = config.GlobalConfig.UpdateTunnelStats(h.cfg.ID, in, out)
				}
			})
		}(clientConn)
	}
}

func (h *IPSpoofHandler) runOverseasListener(l net.Listener, psk []byte) {
	for {
		incomingConn, err := l.Accept()
		if err != nil {
			select {
			case <-h.ctx.Done():
				return
			default:
				system.LogWarn("IP Spoof Overseas accept error: %v", err)
				time.Sleep(100 * time.Millisecond)
				continue
			}
		}
		go func(c net.Conn) {
			defer c.Close()
			// Deadline already covers header read, ACK write, and the
			// handshake — all performed on c before proxying begins.
			_ = c.SetDeadline(time.Now().Add(10 * time.Second))
			buf := make([]byte, 24)
			if _, err := io.ReadFull(c, buf); err != nil {
				system.LogError("IP Spoof Overseas read header: %v", err)
				return
			}
			ack := []byte{0xFE, 0xED, 0xFA, 0xCE}
			if _, err := c.Write(ack); err != nil {
				system.LogError("IP Spoof Overseas write ACK: %v", err)
				return
			}
			secureConn, err := crypto.NewSecureConn(c, psk, false)
			if err != nil {
				system.LogError("IP Spoof Overseas secure handshake: %v", err)
				return
			}
			defer secureConn.Close()
			targetAddr := fmt.Sprintf("127.0.0.1:%d", h.cfg.TargetPort)
			targetConn, err := net.DialTimeout("tcp", targetAddr, 10*time.Second)
			if err != nil {
				system.LogError("IP Spoof Overseas connect to [%s]: %v", targetAddr, err)
				return
			}
			defer targetConn.Close()
			_ = c.SetDeadline(time.Time{})
			ProxyBidirectional(secureConn, targetConn, func(in, out int64) {
				if config.GlobalConfig != nil {
					_ = config.GlobalConfig.UpdateTunnelStats(h.cfg.ID, in, out)
				}
			})
		}(incomingConn)
	}
}