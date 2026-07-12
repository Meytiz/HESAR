package tunnel

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/Meytiz/HESAR/backend/internal/config"
	"github.com/Meytiz/HESAR/backend/internal/system"
	"github.com/Meytiz/HESAR/backend/internal/tunnel/crypto"
)

type SNISpoofHandler struct {
	cfg       *config.TunnelConfig
	ctx       context.Context
	cancel    context.CancelFunc
	listeners []net.Listener
	mu        sync.Mutex
}

func NewSNISpoofHandler(cfg *config.TunnelConfig) *SNISpoofHandler {
	ctx, cancel := context.WithCancel(context.Background())
	return &SNISpoofHandler{cfg: cfg, ctx: ctx, cancel: cancel}
}

func MakeFakeTLSClientHello(sni string) []byte {
	sniLen := len(sni)
	extLen := sniLen + 9
	handshakeBodyLen := 2 + 32 + 1 + 2 + 2 + 1 + 1 + 2 + extLen
	payloadLen := 1 + 3 + handshakeBodyLen

	buf := new(bytes.Buffer)
	buf.WriteByte(0x16)
	buf.Write([]byte{0x03, 0x01})
	buf.Write([]byte{byte((payloadLen >> 8) & 0xFF), byte(payloadLen & 0xFF)})
	buf.WriteByte(0x01)
	buf.Write([]byte{0x00, byte((handshakeBodyLen >> 8) & 0xFF), byte(handshakeBodyLen & 0xFF)})
	buf.Write([]byte{0x03, 0x03})

	var random [32]byte
	if _, err := io.ReadFull(rand.Reader, random[:]); err != nil {
		for i := range random {
			random[i] = byte(i + 1)
		}
	}
	buf.Write(random[:])

	buf.WriteByte(0x00)
	buf.Write([]byte{0x00, 0x02})
	buf.Write([]byte{0x13, 0x01})
	buf.WriteByte(0x01)
	buf.WriteByte(0x00)

	buf.Write([]byte{byte((extLen >> 8) & 0xFF), byte(extLen & 0xFF)})
	buf.Write([]byte{0x00, 0x00})
	sniListLen := sniLen + 5
	buf.Write([]byte{byte((sniListLen >> 8) & 0xFF), byte(sniListLen & 0xFF)})
	sniNameLen := sniLen + 3
	buf.Write([]byte{byte((sniNameLen >> 8) & 0xFF), byte(sniNameLen & 0xFF)})
	buf.WriteByte(0x00)
	buf.Write([]byte{byte((sniLen >> 8) & 0xFF), byte(sniLen & 0xFF)})
	buf.WriteString(sni)

	return buf.Bytes()
}

func (h *SNISpoofHandler) Start() error {
	keyHash := sha256.Sum256([]byte(h.cfg.EncryptionKey))
	sni := h.cfg.SpoofSNI
	if sni == "" {
		sni = "www.aparat.com"
	}
	if h.cfg.Mode == "iran" {
		ports, err := ParsePorts(h.cfg.LocalPorts)
		if err != nil {
			return fmt.Errorf("SNI Spoof iran parse ports: %w", err)
		}
		h.mu.Lock()
		for _, port := range ports {
			l, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
			if err != nil {
				h.mu.Unlock()
				h.Stop()
				return fmt.Errorf("SNI Spoof listen port %d: %w", port, err)
			}
			h.listeners = append(h.listeners, l)
			go h.runIranListener(l, keyHash[:], sni)
		}
		h.mu.Unlock()
		system.LogInfo("SNI Spoof Iran tunnel [%s] (SNI: %s) started on ports: %s", h.cfg.Name, sni, h.cfg.LocalPorts)
	} else if h.cfg.Mode == "overseas" {
		l, err := net.Listen("tcp", fmt.Sprintf(":%d", h.cfg.RemotePort))
		if err != nil {
			return fmt.Errorf("SNI Spoof overseas listen port %d: %w", h.cfg.RemotePort, err)
		}
		h.mu.Lock()
		h.listeners = append(h.listeners, l)
		h.mu.Unlock()
		go h.runOverseasListener(l, keyHash[:])
		system.LogInfo("SNI Spoof Overseas tunnel [%s] started on port: %d", h.cfg.Name, h.cfg.RemotePort)
	} else {
		return fmt.Errorf("unknown mode: %s", h.cfg.Mode)
	}
	return nil
}

func (h *SNISpoofHandler) Stop() {
	h.cancel()
	h.mu.Lock()
	for _, l := range h.listeners {
		_ = l.Close()
	}
	h.listeners = nil
	h.mu.Unlock()
	system.LogInfo("SNI Spoof tunnel [%s] stopped", h.cfg.Name)
}

func (h *SNISpoofHandler) runIranListener(l net.Listener, masterKey []byte, sni string) {
	for {
		clientConn, err := l.Accept()
		if err != nil {
			select {
			case <-h.ctx.Done():
				return
			default:
				system.LogWarn("SNI Spoof Iran accept error: %v", err)
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
				system.LogError("SNI Spoof Iran connect to [%s]: %v", remoteAddr, err)
				return
			}
			defer remoteConn.Close()
			hello := MakeFakeTLSClientHello(sni)
			if _, err := remoteConn.Write(hello); err != nil {
				system.LogError("SNI Spoof Iran send ClientHello: %v", err)
				return
			}
			resp := make([]byte, 7)
			if _, err := io.ReadFull(remoteConn, resp); err != nil {
				system.LogError("SNI Spoof Iran read ACK: %v", err)
				return
			}
			secureConn, err := crypto.NewSecureConn(remoteConn, masterKey, true)
			if err != nil {
				system.LogError("SNI Spoof Iran secure handshake: %v", err)
				return
			}
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

func (h *SNISpoofHandler) runOverseasListener(l net.Listener, masterKey []byte) {
	helloLen := len(MakeFakeTLSClientHello("www.aparat.com"))
	for {
		incomingConn, err := l.Accept()
		if err != nil {
			select {
			case <-h.ctx.Done():
				return
			default:
				system.LogWarn("SNI Spoof Overseas accept error: %v", err)
				time.Sleep(100 * time.Millisecond)
				continue
			}
		}
		go func(c net.Conn) {
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(10 * time.Second))
			buf := make([]byte, helloLen)
			if _, err := io.ReadFull(c, buf); err != nil {
				system.LogError("SNI Spoof Overseas read ClientHello: %v", err)
				return
			}
			ack := []byte{0x16, 0x03, 0x03, 0x00, 0x02, 0x02, 0x00}
			if _, err := c.Write(ack); err != nil {
				system.LogError("SNI Spoof Overseas write ACK: %v", err)
				return
			}
			secureConn, err := crypto.NewSecureConn(c, masterKey, false)
			if err != nil {
				system.LogError("SNI Spoof Overseas secure handshake: %v", err)
				return
			}
			defer secureConn.Close()
			targetAddr := fmt.Sprintf("127.0.0.1:%d", h.cfg.TargetPort)
			targetConn, err := net.DialTimeout("tcp", targetAddr, 10*time.Second)
			if err != nil {
				system.LogError("SNI Spoof Overseas connect to [%s]: %v", targetAddr, err)
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