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
	// pool bounds how many connections may be simultaneously dialing out
	// and performing the secure handshake (see pool.go). It does NOT
	// limit the number of already-established, long-lived tunnel sessions.
	pool *ConnPool
}

func NewTCPHandler(cfg *config.TunnelConfig) *TCPHandler {
	ctx, cancel := context.WithCancel(context.Background())
	return &TCPHandler{cfg: cfg, ctx: ctx, cancel: cancel, pool: NewConnPool(DefaultMaxConcurrentHandshakes)}
}

func (h *TCPHandler) Start() error {
	// psk (pre-shared key) is derived from the configured EncryptionKey.
	// It is used ONLY to authenticate the ephemeral X25519 handshake
	// (via HMAC) and as additional HKDF input material — never directly
	// as a static encryption key. Actual session keys are derived from a
	// fresh ephemeral Diffie-Hellman exchange performed on every
	// connection, giving true forward secrecy: compromise of the PSK
	// does not allow decryption of previously recorded traffic.
	psk := sha256.Sum256([]byte(h.cfg.EncryptionKey))
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
			go h.runIranListener(l, psk[:])
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
		go h.runOverseasListener(l, psk[:])
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

func (h *TCPHandler) runIranListener(l net.Listener, psk []byte) {
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
		// Accept() is never blocked: the connection is immediately handed
		// off to a new goroutine. Concurrency is capped *inside* that
		// goroutine by acquiring a pool slot before dialing out, so at
		// most DefaultMaxConcurrentHandshakes dial+handshake sequences run
		// at the same time; anything beyond that queues here
		// asynchronously until a slot frees up (thread-pool + async
		// semantics, bounded parallel workers, unbounded backlog).
		go func(c net.Conn) {
			defer c.Close()

			if err := h.pool.Acquire(h.ctx); err != nil {
				return // tunnel stopped while waiting for a free slot
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
			remoteConn, err := net.DialTimeout("tcp", remoteAddr, 10*time.Second)
			if err != nil {
				system.LogError("TCP Iran connect to [%s]: %v", remoteAddr, err)
				return
			}
			defer remoteConn.Close()

			// The mutual X25519 handshake performs a full round-trip
			// (write msg1, read msg2) on remoteConn. A read/write deadline
			// on remoteConn is required here, otherwise a hung/unresponsive
			// overseas peer would block this goroutine (and leak the fd,
			// and its pool slot) indefinitely.
			_ = remoteConn.SetDeadline(time.Now().Add(10 * time.Second))
			secureConn, err := crypto.NewSecureConn(remoteConn, psk, true)
			if err != nil {
				system.LogError("TCP Iran secure handshake: %v", err)
				return
			}
			_ = remoteConn.SetDeadline(time.Time{})
			defer secureConn.Close()

			// Handshake succeeded — release the pool slot *before*
			// entering the potentially long-lived proxy loop, so
			// already-established sessions never starve new connections
			// that are waiting for a free handshake slot.
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

func (h *TCPHandler) runOverseasListener(l net.Listener, psk []byte) {
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

			// Deadline already covers the full mutual handshake
			// (read msg1, write msg2) performed directly on c.
			_ = c.SetDeadline(time.Now().Add(10 * time.Second))
			secureConn, err := crypto.NewSecureConn(c, psk, false)
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
