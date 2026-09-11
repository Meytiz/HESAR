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
			// tls.DialWithDialer completes the handshake itself, bounded by the
			// dialer timeout (crypto/tls's dial() derives ONE context from
			// dialer.Timeout and passes it to both DialContext and
			// HandshakeContext), so no separate handshake deadline is needed
			// on this side — unlike the overseas side, which accepts raw
			// connections and must drive the handshake explicitly.
			dialer := &net.Dialer{Timeout: 10 * time.Second}
			tlsConn, err := tls.DialWithDialer(dialer, "tcp", remoteAddr, clientConf)
			if err != nil {
				system.LogError("TLS fallback Iran dial [%s]: %v", remoteAddr, err)
				return
			}
			defer tlsConn.Close()

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

			// vNext fix (transport was 100% broken before this): the
			// handshake is NOT completed by crypto/tls's listener —
			// tls.Listen/tls.NewListener only wrap the accepted raw conn
			// with tls.Server, and the handshake happens lazily on the
			// first Read/Write. The previous code inspected
			// ConnectionState().NegotiatedProtocol immediately after Accept,
			// i.e. before any I/O, where it is always the zero value "", so
			// the ALPN check rejected *every* legitimate session and the
			// `tls` protocol could never proxy a single byte.
			//
			// Drive the handshake explicitly here. Bounding it with
			// tlsHandshakeTimeout is what that constant was declared for, and
			// it also closes a resource-starvation hole: the goroutine holds
			// a slot from the shared ConnPool, so an unbounded
			// client-that-connects-but-never-handshakes could wedge all pool
			// slots permanently.
			tlsConn, ok := c.(*tls.Conn)
			if !ok {
				// tls.Listen always yields a *tls.Conn; anything else means
				// the connection was not wrapped, so it cannot be
				// authenticated — refuse it rather than proxying plaintext.
				system.LogError("TLS fallback Overseas: accepted conn is %T, expected *tls.Conn — rejecting", c)
				h.pool.Release()
				return
			}
			hsCtx, hsCancel := context.WithTimeout(h.ctx, tlsHandshakeTimeout)
			hsErr := tlsConn.HandshakeContext(hsCtx)
			hsCancel()
			if hsErr != nil {
				system.LogWarn("TLS fallback Overseas handshake failed: %v", hsErr)
				h.pool.Release()
				return
			}

			// Handshake is complete, so the negotiated ALPN is now real:
			// enforce it to refuse cross-protocol replays.
			if algpn := tlsConn.ConnectionState().NegotiatedProtocol; algpn != AlpnTLS {
				system.LogWarn("TLS fallback Overseas: rejected ALPN %q", algpn)
				h.pool.Release()
				return
			}

			targetAddr := fmt.Sprintf("127.0.0.1:%d", h.cfg.TargetPort)
			targetConn, err := net.DialTimeout("tcp", targetAddr, 10*time.Second)
			h.pool.Release()
			if err != nil {
				system.LogError("TLS fallback Overseas connect to [%s]: %v", targetAddr, err)
				return
			}
			defer targetConn.Close()

			ProxyBidirectional(tlsConn, targetConn, func(in, out int64) {
				if config.GlobalConfig != nil {
					_ = config.GlobalConfig.UpdateTunnelStats(h.cfg.ID, in, out)
				}
			})
		}(incomingConn)
	}
}
