package tunnel

// TLS-over-TCP fallback transport.
//
// Purpose: when UDP is filtered (QUIC cannot complete its handshake),
// tunnels still need a secure application transport. This handler runs the
// SAME authentication model as the QUIC transport — TLS 1.3 with the
// deterministic PSK-derived Ed25519 certificate pin (see quic.go) — over
// plain TCP, one TLS connection per local connection.
//
//	QUIC / HTTP-3  (primary)
//	    ↓  UDP filtered
//	TLS 1.3 + TCP  (this handler — NO insecure downgrade: TLS 1.3 only,
//	                same pin-based authentication, same EncryptionKey)
//
// ALPN "hesar-tls/1" distinguishes this transport from the QUIC one.

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/Meytiz/HESAR/backend/internal/config"
	"github.com/Meytiz/HESAR/backend/internal/system"
)

// AlpnTLS is the ALPN token of the TLS fallback transport.
const AlpnTLS = "hesar-tls/1"

const tlsHandshakeTimeout = 10 * time.Second

func fallbackServerTLSConfig(cert *tls.Certificate) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{*cert},
		NextProtos:   []string{AlpnTLS},
		MinVersion:   tls.VersionTLS13,
	}
}

// TLSFallbackHandler implements the TLS 1.3-over-TCP fallback transport.
type TLSFallbackHandler struct {
	cfg    *config.TunnelConfig
	ctx    context.Context
	cancel context.CancelFunc

	mu        sync.Mutex
	listeners []net.Listener
	pool      *ConnPool

	psk  []byte
	cert *tls.Certificate
	pin  []byte // raw Ed25519 public key bytes
}

// NewTLSFallbackHandler constructs a fallback-transport handler.
func NewTLSFallbackHandler(cfg *config.TunnelConfig) *TLSFallbackHandler {
	ctx, cancel := context.WithCancel(context.Background())
	return &TLSFallbackHandler{
		cfg:    cfg,
		ctx:    ctx,
		cancel: cancel,
		pool:   NewConnPool(DefaultMaxConcurrentHandshakes),
	}
}

// Start implements TunnelHandler.
func (h *TLSFallbackHandler) Start() error {
	psk := sha256.Sum256([]byte(h.cfg.EncryptionKey))
	h.psk = psk[:]

	cert, pub, err := DeriveQUICCert(h.psk)
	if err != nil {
		return fmt.Errorf("TLS fallback derive certificate: %w", err)
	}
	h.cert = cert
	h.pin = []byte(pub)

	switch h.cfg.Mode {
	case "iran":
		return h.startIran()
	case "overseas":
		return h.startOverseas()
	default:
		return fmt.Errorf("unknown mode: %s", h.cfg.Mode)
	}
}

func (h *TLSFallbackHandler) startIran() error {
	ports, err := ParsePorts(h.cfg.LocalPorts)
	if err != nil {
		return fmt.Errorf("TLS fallback iran parse ports: %w", err)
	}
	h.mu.Lock()
	for _, port := range ports {
		l, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
		if err != nil {
			h.mu.Unlock()
			h.Stop()
			return fmt.Errorf("TLS fallback listen port %d: %w", port, err)
		}
		h.listeners = append(h.listeners, l)
		go h.runIranListener(l)
	}
	h.mu.Unlock()
	system.LogInfo("TLS-fallback Iran tunnel [%s] started on ports: %s", h.cfg.Name, h.cfg.LocalPorts)
	return nil
}

func (h *TLSFallbackHandler) startOverseas() error {
	l, err := tls.Listen("tcp", fmt.Sprintf(":%d", h.cfg.RemotePort), fallbackServerTLSConfig(h.cert))
	if err != nil {
		return fmt.Errorf("TLS fallback overseas listen port %d: %w", h.cfg.RemotePort, err)
	}
	h.mu.Lock()
	h.listeners = append(h.listeners, l)
	h.mu.Unlock()
	go h.runOverseasListener(l)
	system.LogInfo("TLS-fallback Overseas tunnel [%s] listening on tcp/%d", h.cfg.Name, h.cfg.RemotePort)
	return nil
}

// Stop implements TunnelHandler.
func (h *TLSFallbackHandler) Stop() {
	h.cancel()
	h.mu.Lock()
	for _, l := range h.listeners {
		_ = l.Close()
	}
	h.listeners = nil
	h.mu.Unlock()
	system.LogInfo("TLS-fallback tunnel [%s] stopped", h.cfg.Name)
}

func (h *TLSFallbackHandler) runIranListener(l net.Listener) {
	clientConf := &tls.Config{
		InsecureSkipVerify:    true,
		VerifyPeerCertificate: pinVerifier(ed25519.PublicKey(h.pin)),
		NextProtos:            []string{AlpnTLS},
		MinVersion:            tls.VersionTLS13,
	}

	for {
		clientConn, err := l.Accept()
		if err != nil {
			select {
			case <-h.ctx.Done():
				return
			default:
				system.LogWarn("TLS fallback Iran accept error: %v", err)
				time.Sleep(100 * time.Millisecond)
				continue
			}
		}
		go func(c net.Conn) {
			defer c.Close()

			acqCtx, cancel := context.WithTimeout(h.ctx, 30*time.Second)
			err := h.pool.Acquire(acqCtx)
			cancel()
			if err != nil {
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

			remoteAddr := net.JoinHostPort(h.cfg.RemoteIP, strconv.Itoa(h.cfg.RemotePort))
			dialer := &net.Dialer{Timeout: 10 * time.Second}
			tlsConn, err := tls.DialWithDialer(dialer, "tcp", remoteAddr, clientConf)
			if err != nil {
				system.LogError("TLS fallback Iran dial [%s]: %v", remoteAddr, err)
				return
			}
			defer tlsConn.Close()

			if err := tlsConn.HandshakeContext(h.ctx); err != nil {
				system.LogError("TLS fallback Iran handshake: %v", err)
				return
			}

			release()

			ProxyBidirectional(c, tlsConn, func(in, out int64) {
				if config.GlobalConfig != nil {
					_ = config.GlobalConfig.UpdateTunnelStats(h.cfg.ID, in, out)
				}
			})
		}(clientConn)
	}
}

func (h *TLSFallbackHandler) runOverseasListener(l net.Listener) {
	for {
		incomingConn, err := l.Accept()
		if err != nil {
			select {
			case <-h.ctx.Done():
				return
			default:
				system.LogWarn("TLS fallback Overseas accept error: %v", err)
				time.Sleep(100 * time.Millisecond)
				continue
			}
		}
		go func(c net.Conn) {
			defer c.Close()

			if err := h.pool.Acquire(h.ctx); err != nil {
				return
			}

			// tls.Listener already performed the handshake inside Accept;
			// enforce ALPN to refuse cross-protocol replays.
			tlsConn, ok := c.(*tls.Conn)
			if ok {
				if tlsConn.ConnectionState().NegotiatedProtocol != AlpnTLS {
					system.LogWarn("TLS fallback Overseas: rejected ALPN %q", tlsConn.ConnectionState().NegotiatedProtocol)
					h.pool.Release()
					return
				}
			}

			targetAddr := fmt.Sprintf("127.0.0.1:%d", h.cfg.TargetPort)
			targetConn, err := net.DialTimeout("tcp", targetAddr, 10*time.Second)
			h.pool.Release()
			if err != nil {
				system.LogError("TLS fallback Overseas connect to [%s]: %v", targetAddr, err)
				return
			}
			defer targetConn.Close()

			ProxyBidirectional(c, targetConn, func(in, out int64) {
				if config.GlobalConfig != nil {
					_ = config.GlobalConfig.UpdateTunnelStats(h.cfg.ID, in, out)
				}
			})
		}(incomingConn)
	}
}
