package tunnel

// QUIC transport — the primary vNext transport of HESAR.
//
// Architecture:
//
//	TCP application traffic  →  QUIC streams   (one stream per local TCP conn,
//	                             multiplexed over ONE shared QUIC connection)
//	UDP application traffic  →  temporarily disabled pending flow redesign
//
// Security model:
//   - TLS 1.3 only (quic-go enforces TLS 1.3 for QUIC v1).
//   - Authentication is PSK-based WITHOUT exposing the PSK: both sides
//     deterministically derive the SAME Ed25519 server certificate from
//     sha256(EncryptionKey) via HKDF. Both peers present a certificate and
//     pin the expected public key in VerifyPeerCertificate. This proves
//     possession of the shared credential, not an individual node identity.
//   - Forward secrecy comes from the ephemeral TLS 1.3 key exchange; the
//     static certificate is an authentication credential only.
//   - ALPN "hesar-quic/2" requires mutual credential verification.
// Native QUIC has a custom ALPN and is not HTTP/3 camouflage. The optional
// auto handler provides WSS fallback and uses an explicit readiness exchange.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	xhkdf "golang.org/x/crypto/hkdf"
	"io"
	"math/big"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Meytiz/HESAR/backend/internal/config"
	"github.com/Meytiz/HESAR/backend/internal/system"
	"github.com/quic-go/quic-go"
)

const (
	// AlpnQUIC is the ALPN token of the QUIC transport. Bumping it is the
	// protocol-versioning mechanism: peers advertising different ALPNs
	// fail the TLS handshake loudly instead of misinterpreting frames.
	AlpnQUIC     = "hesar-quic/2"
	AlpnAutoQUIC = "hesar-auto/1"

	quicDialTimeout = 8 * time.Second
	quicIdleTimeout = 30 * time.Second
)

// quicCertSalt / quicCertInfo domain-separate the deterministic certificate
// derivation from every other HKDF use in the codebase.
var (
	quicCertSalt = []byte("HESAR_QUIC_CERT_SALT_v1")
	quicCertInfo = []byte("HESAR_QUIC_ED25519_CERT_v1")
)

// DeriveQUICCert deterministically derives the tunnel's Ed25519 certificate
// from the pre-shared key, and returns it together with the public key that
// clients must pin. Identical inputs always yield the identical credential,
// which is what lets two peers that only share a PSK authenticate each
// other with no PKI and no certificate exchange in the config.
func DeriveQUICCert(psk []byte) (*tls.Certificate, ed25519.PublicKey, error) {
	h := xhkdf.New(sha256.New, psk, quicCertSalt, quicCertInfo)
	seed := make([]byte, ed25519.SeedSize)
	if _, err := io.ReadFull(h, seed); err != nil {
		return nil, nil, fmt.Errorf("derive cert seed: %w", err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("derive cert serial: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "hesar"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		return nil, nil, fmt.Errorf("create certificate: %w", err)
	}
	cert := &tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
	}
	return cert, pub, nil
}

// pinVerifier returns a VerifyPeerCertificate callback that accepts a chain
// only if the leaf's Ed25519 public key equals the pinned key. Standard
// chain validation is deliberately skipped (self-signed, deterministic
// credential) — the pin IS the trust anchor.
func pinVerifier(pin ed25519.PublicKey) func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errors.New("no certificate presented")
		}
		leaf, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("parse leaf certificate: %w", err)
		}
		pub, ok := leaf.PublicKey.(ed25519.PublicKey)
		if !ok {
			return errors.New("leaf certificate is not Ed25519")
		}
		if !ed25519PublicKeyEqual(pub, pin) {
			return errors.New("certificate pin mismatch: wrong EncryptionKey or MITM attempt")
		}
		return nil
	}
}

func ed25519PublicKeyEqual(a, b ed25519.PublicKey) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

func serverTLSConfig(cert *tls.Certificate) *tls.Config {
	// Both peers must prove possession of the shared credential. Requiring
	// a certificate alone is insufficient: verify its pinned public key too.
	pin := cert.PrivateKey.(ed25519.PrivateKey).Public().(ed25519.PublicKey)
	return &tls.Config{
		Certificates:          []tls.Certificate{*cert},
		ClientAuth:            tls.RequireAnyClientCert,
		VerifyPeerCertificate: pinVerifier(pin),
		NextProtos:            []string{AlpnQUIC},
		MinVersion:            tls.VersionTLS13,
	}
}

func clientTLSConfig(cert *tls.Certificate, pin ed25519.PublicKey) *tls.Config {
	return &tls.Config{
		Certificates:          []tls.Certificate{*cert},
		InsecureSkipVerify:    true, // trust is established by the pin below
		VerifyPeerCertificate: pinVerifier(pin),
		NextProtos:            []string{AlpnQUIC},
		MinVersion:            tls.VersionTLS13,
	}
}

// quicStreamConn adapts a quic.Stream to net.Conn so the shared
// ProxyBidirectional helper can be reused unchanged.
type quicStreamConn struct {
	s           *quic.Stream
	laddr       net.Addr
	raddr       net.Addr
	writeClosed atomic.Bool
}

func (q *quicStreamConn) Read(b []byte) (int, error)  { return q.s.Read(b) }
func (q *quicStreamConn) Write(b []byte) (int, error) { return q.s.Write(b) }

// Close terminates both directions of the stream. quic.Stream.Close only
// closes the *send* direction, so without the explicit CancelRead the receive
// side lingers — holding a stream slot and flow-control credit on the single
// shared QUIC connection — until that connection is torn down.
func (q *quicStreamConn) Close() error {
	q.s.CancelRead(0)
	if !q.writeClosed.Load() {
		q.s.CancelWrite(0)
	}
	return nil
}

// CloseWrite closes just the send direction (i.e. it emits the FIN that lets
// the peer's Read return EOF). ProxyBidirectional calls it through the
// closeWriter interface for prompt, correct half-close teardown; *net.TCPConn
// and *tls.Conn expose the same capability.
func (q *quicStreamConn) CloseWrite() error {
	// Preserve a graceful FIN: resetting after Close can discard queued data.
	q.writeClosed.Store(true)
	return q.s.Close()
}

func (q *quicStreamConn) LocalAddr() net.Addr                { return q.laddr }
func (q *quicStreamConn) RemoteAddr() net.Addr               { return q.raddr }
func (q *quicStreamConn) SetDeadline(t time.Time) error      { return q.s.SetDeadline(t) }
func (q *quicStreamConn) SetReadDeadline(t time.Time) error  { return q.s.SetReadDeadline(t) }
func (q *quicStreamConn) SetWriteDeadline(t time.Time) error { return q.s.SetWriteDeadline(t) }

// QUICHandler implements the QUIC transport for both modes.
type QUICHandler struct {
	cfg    *config.TunnelConfig
	ctx    context.Context
	cancel context.CancelFunc

	mu           sync.Mutex
	tcpListeners []net.Listener
	udpSockets   []net.PacketConn
	quicListener *quic.Listener
	serverConns  map[*quic.Conn]struct{}
	pool         *ConnPool

	psk    []byte
	cert   *tls.Certificate
	pin    ed25519.PublicKey
	useUDP bool

	// iran side: one shared QUIC connection to the overseas node; every
	// local TCP connection becomes a stream on it.
	dialMu          sync.Mutex
	clientConn      *quic.Conn
	clientTransport *quic.Transport
	clientSocket    *net.UDPConn
}

// NewQUICHandler constructs a handler for the QUIC transport.
func NewQUICHandler(cfg *config.TunnelConfig) *QUICHandler {
	ctx, cancel := context.WithCancel(context.Background())
	return &QUICHandler{
		cfg:         cfg,
		ctx:         ctx,
		cancel:      cancel,
		pool:        NewConnPool(0),
		serverConns: make(map[*quic.Conn]struct{}),
	}
}

// Start implements TunnelHandler.
func (h *QUICHandler) Start() error {
	if _, err := underlayAddress(h.ctx, h.cfg); err != nil {
		return err
	}
	if err := h.prepare(); err != nil {
		return err
	}
	switch h.cfg.Mode {
	case "iran":
		return h.startIran()
	case "overseas":
		return h.startOverseas()
	default:
		return fmt.Errorf("unknown mode: %s", h.cfg.Mode)
	}
}

func (h *QUICHandler) prepare() error {
	// Fail closed rather than silently provide a broken UDP relay. Keep the
	// experimental implementation isolated until flow routing is redesigned.
	if h.cfg.QUICEnableUDP {
		return errors.New("QUIC UDP relay is temporarily disabled; set quic_enable_udp=false")
	}
	psk := sha256.Sum256([]byte(h.cfg.EncryptionKey))
	h.psk = psk[:]

	cert, pin, err := DeriveQUICCert(h.psk)
	if err != nil {
		return fmt.Errorf("QUIC derive certificate: %w", err)
	}
	h.cert = cert
	h.pin = pin
	h.useUDP = false

	return nil
}

func (h *QUICHandler) startIran() error {
	ports, err := ParsePorts(h.cfg.LocalPorts)
	if err != nil {
		return fmt.Errorf("QUIC iran parse ports: %w", err)
	}
	h.mu.Lock()
	for _, port := range ports {
		l, err := net.Listen("tcp", listenAddr(h.cfg, port))
		if err != nil {
			h.mu.Unlock()
			h.Stop()
			return fmt.Errorf("QUIC listen tcp port %d: %w", port, err)
		}
		h.tcpListeners = append(h.tcpListeners, l)
		go h.runIranTCPListener(l)

	}
	h.mu.Unlock()

	system.LogInfo("QUIC Iran tunnel [%s] started on ports: %s (udp-datagrams: %v)", h.cfg.Name, h.cfg.LocalPorts, h.useUDP)
	return nil
}

func (h *QUICHandler) startOverseas() error {
	// ListenAddr owns its UDP socket and transport; closing the listener
	// releases both, unlike a manually created Transport with a borrowed socket.
	tlsConfig := serverTLSConfig(h.cert)
	if h.cfg.Protocol == ProtocolAuto {
		tlsConfig.NextProtos = []string{AlpnAutoQUIC}
	}
	ln, err := quic.ListenAddr(listenAddr(h.cfg, h.cfg.RemotePort), tlsConfig, &quic.Config{
		MaxIdleTimeout:          quicIdleTimeout,
		HandshakeIdleTimeout:    dialTimeout(h.cfg),
		InitialPacketSize:       1200,
		DisablePathMTUDiscovery: h.cfg.QUICDisablePMTU || h.cfg.UnderlayInterface != "",
		KeepAlivePeriod:         10 * time.Second,
		// -1 disables incoming unidirectional streams (0 would select the
		// library default); this transport only opens bidirectional streams.
		MaxIncomingStreams:    maxSessionsPerTunnel,
		MaxIncomingUniStreams: -1,
		EnableDatagrams:       h.useUDP,
	})
	if err != nil {
		return fmt.Errorf("QUIC overseas quic listen: %w", err)
	}
	h.mu.Lock()
	h.quicListener = ln
	h.mu.Unlock()

	go h.runOverseasAcceptLoop(ln)
	system.LogInfo("QUIC Overseas tunnel [%s] listening on udp/%d (datagrams: %v)", h.cfg.Name, h.cfg.RemotePort, h.useUDP)
	return nil
}

// Stop implements TunnelHandler.
func (h *QUICHandler) Stop() {
	h.cancel()
	h.pool.CloseAll()
	h.mu.Lock()
	for conn := range h.serverConns {
		_ = conn.CloseWithError(0, "tunnel stopped")
	}
	for _, l := range h.tcpListeners {
		_ = l.Close()
	}
	h.tcpListeners = nil
	for _, pc := range h.udpSockets {
		_ = pc.Close()
	}
	h.udpSockets = nil
	if h.quicListener != nil {
		_ = h.quicListener.Close()
		h.quicListener = nil
	}
	h.mu.Unlock()

	h.dialMu.Lock()
	if h.clientConn != nil {
		_ = h.clientConn.CloseWithError(0, "tunnel stopped")
		h.clientConn = nil
	}
	h.closeClientUnderlay()
	h.dialMu.Unlock()
	system.LogInfo("QUIC tunnel [%s] stopped", h.cfg.Name)
}

// getSharedConn lazily dials (and redials) the single multiplexed QUIC
// connection to the overseas node.
func (h *QUICHandler) getSharedConn() (*quic.Conn, error) {
	h.dialMu.Lock()
	defer h.dialMu.Unlock()
	source, err := underlayAddress(h.ctx, h.cfg)
	if err != nil {
		return nil, err
	}

	if h.clientConn != nil {
		select {
		case <-h.clientConn.Context().Done():
			h.clientConn = nil
			h.closeClientUnderlay()
		default:
			return h.clientConn, nil
		}
	}

	remoteAddr := net.JoinHostPort(h.cfg.RemoteIP, strconv.Itoa(h.cfg.RemotePort))
	dialCtx, cancel := context.WithTimeout(h.ctx, dialTimeout(h.cfg))
	defer cancel()

	tlsConfig := clientTLSConfig(h.cert, h.pin)
	if h.cfg.Protocol == ProtocolAuto {
		tlsConfig.NextProtos = []string{AlpnAutoQUIC}
	}
	quicConfig := &quic.Config{
		MaxIdleTimeout:          quicIdleTimeout,
		KeepAlivePeriod:         10 * time.Second,
		HandshakeIdleTimeout:    dialTimeout(h.cfg),
		InitialPacketSize:       1200,
		DisablePathMTUDiscovery: h.cfg.QUICDisablePMTU,
		EnableDatagrams:         h.useUDP,
	}
	quicConfig.DisablePathMTUDiscovery = h.cfg.QUICDisablePMTU || h.cfg.UnderlayInterface != ""
	var conn *quic.Conn
	if source == nil {
		conn, err = quic.DialAddr(dialCtx, remoteAddr, tlsConfig, quicConfig)
	} else {
		peer := &net.UDPAddr{IP: net.ParseIP(h.cfg.RemoteIP).To4(), Port: h.cfg.RemotePort}
		h.clientSocket, err = net.ListenUDP("udp4", &net.UDPAddr{IP: source})
		if err == nil {
			h.clientTransport = &quic.Transport{Conn: h.clientSocket}
			conn, err = h.clientTransport.Dial(dialCtx, peer, tlsConfig, quicConfig)
		}
	}
	if err != nil {
		h.closeClientUnderlay()
		return nil, fmt.Errorf("QUIC dial %s: %w", remoteAddr, err)
	}
	h.clientConn = conn
	return conn, nil
}

// Caller holds dialMu; quic.Transport borrows the explicitly bound socket.
func (h *QUICHandler) closeClientUnderlay() {
	if h.clientTransport != nil {
		_ = h.clientTransport.Close()
		h.clientTransport = nil
	}
	if h.clientSocket != nil {
		_ = h.clientSocket.Close()
		h.clientSocket = nil
	}
}

func (h *QUICHandler) runIranTCPListener(l net.Listener) {
	for {
		clientConn, err := l.Accept()
		if err != nil {
			select {
			case <-h.ctx.Done():
				return
			default:
				system.LogWarn("QUIC Iran accept error: %v", err)
				time.Sleep(100 * time.Millisecond)
				continue
			}
		}
		h.pool.Run(clientConn, func(c net.Conn) {
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

			qconn, err := h.getSharedConn()
			if err != nil {
				system.LogError("QUIC Iran: %v", err)
				return
			}
			streamCtx, cancel := context.WithTimeout(h.ctx, quicDialTimeout)
			stream, err := qconn.OpenStreamSync(streamCtx)
			cancel()
			if err != nil {
				system.LogError("QUIC Iran open stream: %v", err)
				// A stream-capacity timeout is not a connection failure.
				// getSharedConn replaces only connections whose context ended.
				return
			}

			// Opening the stream completed the per-connection setup work;
			// release the handshake slot before the long-lived proxy loop.
			release()

			sc := &quicStreamConn{s: stream, laddr: c.LocalAddr(), raddr: c.RemoteAddr()}
			defer sc.Close()
			proxyWithTimeout(h.ctx, c, sc, func(in, out int64) {
				if config.GlobalConfig != nil {
					_ = config.GlobalConfig.UpdateTunnelStats(h.cfg.ID, in, out)
				}
			}, idleTimeout(h.cfg))
		})
	}
}

func (h *QUICHandler) runOverseasAcceptLoop(ln *quic.Listener) {
	for {
		qconn, err := ln.Accept(h.ctx)
		if err != nil {
			select {
			case <-h.ctx.Done():
				return
			default:
				system.LogWarn("QUIC Overseas accept error: %v", err)
				time.Sleep(100 * time.Millisecond)
				continue
			}
		}
		h.mu.Lock()
		if h.ctx.Err() != nil || len(h.serverConns) >= 32 {
			h.mu.Unlock()
			_ = qconn.CloseWithError(0, "session capacity reached or tunnel stopped")
			continue
		}
		h.serverConns[qconn] = struct{}{}
		h.mu.Unlock()
		go h.serveOverseasConn(qconn)
	}
}

func (h *QUICHandler) serveOverseasConn(qconn *quic.Conn) {
	defer func() {
		_ = qconn.CloseWithError(0, "session ended")
		h.mu.Lock()
		delete(h.serverConns, qconn)
		h.mu.Unlock()
	}()

	for {
		stream, err := qconn.AcceptStream(h.ctx)
		if err != nil {
			return
		}
		sc := &quicStreamConn{s: stream, laddr: qconn.LocalAddr(), raddr: qconn.RemoteAddr()}
		h.pool.Run(sc, func(c net.Conn) {
			if err := h.pool.Acquire(qconn.Context()); err != nil {
				return
			}
			if h.cfg.Protocol == ProtocolAuto {
				_ = c.SetDeadline(time.Now().Add(dialTimeout(h.cfg)))
				var hello [1]byte
				if _, err := io.ReadFull(c, hello[:]); err != nil || hello[0] != 1 {
					h.pool.Release()
					return
				}
			}
			targetAddr := targetAddr(h.cfg)
			dialer := &net.Dialer{Timeout: dialTimeout(h.cfg)}
			targetConn, err := dialer.DialContext(qconn.Context(), "tcp", targetAddr)
			h.pool.Release()
			if err != nil {
				system.LogError("QUIC Overseas connect to [%s]: %v", targetAddr, err)
				return
			}
			defer targetConn.Close()
			if h.cfg.Protocol == ProtocolAuto {
				if _, err := c.Write([]byte{0}); err != nil {
					return
				}
				_ = c.SetDeadline(time.Time{})
			}
			proxyWithTimeout(qconn.Context(), c, targetConn, func(in, out int64) {
				if config.GlobalConfig != nil {
					_ = config.GlobalConfig.UpdateTunnelStats(h.cfg.ID, in, out)
				}
			}, idleTimeout(h.cfg))
		})
	}
}
