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
	"github.com/xtaci/kcp-go/v5"
)

type KCPHandler struct {
	cfg       *config.TunnelConfig
	ctx       context.Context
	cancel    context.CancelFunc
	listeners []net.Listener
	mu        sync.Mutex
	// pool bounds how many connections may be simultaneously dialing out
	// and performing the secure handshake (see pool.go).
	pool *ConnPool
}

func NewKCPHandler(cfg *config.TunnelConfig) *KCPHandler {
	ctx, cancel := context.WithCancel(context.Background())
	return &KCPHandler{cfg: cfg, ctx: ctx, cancel: cancel, pool: NewConnPool(DefaultMaxConcurrentHandshakes)}
}

func applyKCPOptions(sess *kcp.UDPSession, mode string) {
	switch mode {
	case "fast3":
		sess.SetNoDelay(1, 10, 2, 1)
		sess.SetWindowSize(1024, 1024)
	case "fast2":
		sess.SetNoDelay(1, 20, 2, 1)
		sess.SetWindowSize(768, 768)
	case "fast":
		sess.SetNoDelay(0, 30, 2, 1)
		sess.SetWindowSize(512, 512)
	default:
		sess.SetNoDelay(0, 40, 0, 0)
		sess.SetWindowSize(256, 256)
	}
	sess.SetWriteDelay(false)
	sess.SetACKNoDelay(true)
}

func (h *KCPHandler) Start() error {
	// psk authenticates the ephemeral X25519 handshake performed inside
	// crypto.NewSecureConn (see crypto.go) — it is never used directly as
	// a symmetric encryption key. Session keys are derived from a fresh
	// Diffie-Hellman exchange on every connection (forward secrecy).
	psk := sha256.Sum256([]byte(h.cfg.EncryptionKey))
	if h.cfg.Mode == "iran" {
		ports, err := ParsePorts(h.cfg.LocalPorts)
		if err != nil {
			return fmt.Errorf("KCP iran parse ports: %w", err)
		}
		h.mu.Lock()
		for _, port := range ports {
			l, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
			if err != nil {
				h.mu.Unlock()
				h.Stop()
				return fmt.Errorf("KCP listen port %d: %w", port, err)
			}
			h.listeners = append(h.listeners, l)
			go h.runIranListener(l, psk[:])
		}
		h.mu.Unlock()
		system.LogInfo("KCP Iran tunnel [%s] (mode: %s) started on ports: %s", h.cfg.Name, h.cfg.KCPMode, h.cfg.LocalPorts)
	} else if h.cfg.Mode == "overseas" {
		block, _ := kcp.NewNoneBlockCrypt(nil)
		l, err := kcp.ListenWithOptions(fmt.Sprintf(":%d", h.cfg.RemotePort), block, 10, 3)
		if err != nil {
			return fmt.Errorf("KCP overseas listen port %d: %w", h.cfg.RemotePort, err)
		}
		h.mu.Lock()
		h.listeners = append(h.listeners, l)
		h.mu.Unlock()
		go h.runOverseasListener(l, psk[:])
		system.LogInfo("KCP Overseas tunnel [%s] (mode: %s) started on UDP port: %d", h.cfg.Name, h.cfg.KCPMode, h.cfg.RemotePort)
	} else {
		return fmt.Errorf("unknown mode: %s", h.cfg.Mode)
	}
	return nil
}

func (h *KCPHandler) Stop() {
	h.cancel()
	h.mu.Lock()
	for _, l := range h.listeners {
		_ = l.Close()
	}
	h.listeners = nil
	h.mu.Unlock()
	system.LogInfo("KCP tunnel [%s] stopped", h.cfg.Name)
}

func (h *KCPHandler) runIranListener(l net.Listener, psk []byte) {
	for {
		clientConn, err := l.Accept()
		if err != nil {
			select {
			case <-h.ctx.Done():
				return
			default:
				system.LogWarn("KCP Iran accept error: %v", err)
				time.Sleep(100 * time.Millisecond)
				continue
			}
		}
		go func(c net.Conn) {
			defer c.Close()

			if err := h.pool.Acquire(h.ctx); err != nil {
				return
			}
			released := false
			release := func() {
				if !released {
					released = true
					h.pool.Release()
				}
			}
			defer release()

			_ = c.SetDeadline(time.Now().Add(10 * time.Second))
			remoteAddr := fmt.Sprintf("%s:%d", h.cfg.RemoteIP, h.cfg.RemotePort)
			block, _ := kcp.NewNoneBlockCrypt(nil)
			kcpConn, err := kcp.DialWithOptions(remoteAddr, block, 10, 3)
			if err != nil {
				system.LogError("KCP Iran connect to [%s]: %v", remoteAddr, err)
				return
			}
			defer kcpConn.Close()
			applyKCPOptions(kcpConn, h.cfg.KCPMode)

			// The X25519 handshake performs a full read/write round-trip
			// on kcpConn. Without an explicit deadline here, an
			// unresponsive or malicious overseas peer could stall this
			// goroutine indefinitely, leaking the KCP session, its
			// underlying UDP resources, and its pool slot.
			_ = kcpConn.SetDeadline(time.Now().Add(10 * time.Second))
			secureConn, err := crypto.NewSecureConn(kcpConn, psk, true)
			if err != nil {
				system.LogError("KCP Iran secure handshake: %v", err)
				return
			}
			_ = kcpConn.SetDeadline(time.Time{})
			defer secureConn.Close()

			release()

			_ = c.SetDeadline(time.Time{})
			ProxyBidirectional(c, secureConn, func(in, out int64) {
				if config.GlobalConfig != nil {
					_ = config.GlobalConfig.UpdateTunnelStats(h.cfg.ID, in, out)
				}
			})
		}(clientConn)
	}
}

func (h *KCPHandler) runOverseasListener(l net.Listener, psk []byte) {
	for {
		incomingConn, err := l.Accept()
		if err != nil {
			select {
			case <-h.ctx.Done():
				return
			default:
				system.LogWarn("KCP Overseas accept error: %v", err)
				time.Sleep(100 * time.Millisecond)
				continue
			}
		}
		kcpSess, ok := incomingConn.(*kcp.UDPSession)
		if ok {
			applyKCPOptions(kcpSess, h.cfg.KCPMode)
		}
		go func(c net.Conn) {
			defer c.Close()

			if err := h.pool.Acquire(h.ctx); err != nil {
				return
			}
			released := false
			release := func() {
				if !released {
					released = true
					h.pool.Release()
				}
			}
			defer release()

			// Deadline set before the handshake (read msg1, write msg2)
			// is performed directly on c — already correct.
			_ = c.SetDeadline(time.Now().Add(10 * time.Second))
			secureConn, err := crypto.NewSecureConn(c, psk, false)
			if err != nil {
				system.LogError("KCP Overseas secure handshake: %v", err)
				return
			}
			defer secureConn.Close()
			targetAddr := fmt.Sprintf("127.0.0.1:%d", h.cfg.TargetPort)
			targetConn, err := net.DialTimeout("tcp", targetAddr, 10*time.Second)
			if err != nil {
				system.LogError("KCP Overseas connect to [%s]: %v", targetAddr, err)
				return
			}
			defer targetConn.Close()

			release()

			_ = c.SetDeadline(time.Time{})
			ProxyBidirectional(secureConn, targetConn, func(in, out int64) {
				if config.GlobalConfig != nil {
					_ = config.GlobalConfig.UpdateTunnelStats(h.cfg.ID, in, out)
				}
			})
		}(incomingConn)
	}
}
