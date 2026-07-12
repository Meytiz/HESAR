package tunnel

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/Meytiz/HESAR/backend/internal/config"
	"github.com/Meytiz/HESAR/backend/internal/system"
	"github.com/Meytiz/HESAR/backend/internal/tunnel/crypto"
)

type TCPHandler struct {
	cfg       *config.TunnelConfig
	ctx       context.Context
	cancel    context.CancelFunc
	listeners []net.Listener
	mu        sync.Mutex
}

func NewTCPHandler(cfg *config.TunnelConfig) *TCPHandler {
	ctx, cancel := context.WithCancel(context.Background())
	return &TCPHandler{cfg: cfg, ctx: ctx, cancel: cancel}
}

func (h *TCPHandler) Start() error {
	keyHash := sha256.Sum256([]byte(h.cfg.EncryptionKey))
	if h.cfg.Mode == "iran" {
		ports, err := ParsePorts(h.cfg.LocalPorts)
		if err != nil {
			return fmt.Errorf("TCP iran parse ports: %w", err)
		}
		h.mu.Lock()
		for _, port := range ports {
			l, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
			if err != nil {
				h.mu.Unlock()
				h.Stop()
				return fmt.Errorf("TCP listen port %d: %w", port, err)
			}
			h.listeners = append(h.listeners, l)
			go h.runIranListener(l, keyHash[:])
		}
		h.mu.Unlock()
		system.LogInfo("TCP Iran tunnel [%s] started on ports: %s", h.cfg.Name, h.cfg.LocalPorts)
	} else if h.cfg.Mode == "overseas" {
		l, err := net.Listen("tcp", fmt.Sprintf(":%d", h.cfg.RemotePort))
		if err != nil {
			return fmt.Errorf("TCP overseas listen port %d: %w", h.cfg.RemotePort, err)
		}
		h.mu.Lock()
		h.listeners = append(h.listeners, l)
		h.mu.Unlock()
		go h.runOverseasListener(l, keyHash[:])
		system.LogInfo("TCP Overseas tunnel [%s] started on port: %d", h.cfg.Name, h.cfg.RemotePort)
	} else {
		return fmt.Errorf("unknown mode: %s", h.cfg.Mode)
	}
	return nil
}

func (h *TCPHandler) Stop() {
	h.cancel()
	h.mu.Lock()
	for _, l := range h.listeners {
		_ = l.Close()
	}
	h.listeners = nil
	h.mu.Unlock()
	system.LogInfo("TCP tunnel [%s] stopped", h.cfg.Name)
}

func (h *TCPHandler) runIranListener(l net.Listener, masterKey []byte) {
	for {
		clientConn, err := l.Accept()
		if err != nil {
			select {
			case <-h.ctx.Done():
				return
			default:
				system.LogWarn("TCP Iran accept error: %v", err)
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
				system.LogError("TCP Iran connect to [%s]: %v", remoteAddr, err)
				return
			}
			defer remoteConn.Close()
			secureConn, err := crypto.NewSecureConn(remoteConn, masterKey, true)
			if err != nil {
				system.LogError("TCP Iran secure handshake: %v", err)
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

func (h *TCPHandler) runOverseasListener(l net.Listener, masterKey []byte) {
	for {
		incomingConn, err := l.Accept()
		if err != nil {
			select {
			case <-h.ctx.Done():
				return
			default:
				system.LogWarn("TCP Overseas accept error: %v", err)
				time.Sleep(100 * time.Millisecond)
				continue
			}
		}
		go func(c net.Conn) {
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(10 * time.Second))
			secureConn, err := crypto.NewSecureConn(c, masterKey, false)
			if err != nil {
				system.LogError("TCP Overseas secure handshake: %v", err)
				return
			}
			defer secureConn.Close()
			targetAddr := fmt.Sprintf("127.0.0.1:%d", h.cfg.TargetPort)
			targetConn, err := net.DialTimeout("tcp", targetAddr, 10*time.Second)
			if err != nil {
				system.LogError("TCP Overseas connect to [%s]: %v", targetAddr, err)
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