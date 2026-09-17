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
// No fallback: when a QUIC dial fails (UDP filtered) the error is surfaced
// to the operator, who switches the tunnel to the TCP or KCP transport
// manually. The TLS 1.3-over-TCP fallback transport has been REMOVED —
// every tunnel runs exactly one protocol, which keeps behaviour auditable
// and removes a whole transport (and its ALPN) from the attack surface.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"fmt"
	xhkdf "golang.org/x/crypto/hkdf"
	"io"
	"math/big"
	"net"
	"os"
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
	AlpnQUIC = "hesar-quic/2"

	// envEnableQUICDatagram gates the experimental UDP-over-DATAGRAM path.
	// QUIC DATAGRAM (RFC 9221) is unreliable-by-design; the relay here is
	// best-effort and intentionally kept behind a feature flag until the
	// MASQUE CONNECT-UDP profile is adopted.
	envEnableQUICDatagram = "HESAR_ENABLE_QUIC_DATAGRAM"

	quicDialTimeout   = 8 * time.Second
	quicIdleTimeout   = 30 * time.Second
	quicHandshakeTO   = 8 * time.Second
	maxDatagramFlows  = 4096
	datagramFlowTTL   = 60 * time.Second
	maxDatagramPayLen = 65000
)

// quicCertSalt / quicCertInfo domain-separate the deterministic certificate
// derivation from every other HKDF use in the codebase.
var (
	quicCertSalt = []byte("HESAR_QUIC_CERT_SALT_v1")
	quicCertInfo = []byte("HESAR_QUIC_ED25519_CERT_v1")
)

// datagramEnabled reports whether the experimental UDP relay is enabled.
func datagramEnabled() bool {
	v := os.Getenv(envEnableQUICDatagram)
	if v == "" {
		return false
	}
	b, err := strconv.ParseBool(v)
	return err == nil && b
}

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
	s     *quic.Stream
	laddr net.Addr
	raddr net.Addr
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
	dialMu     sync.Mutex
	clientConn *quic.Conn
}

// NewQUICHandler constructs a handler for the QUIC transport.
func NewQUICHandler(cfg *config.TunnelConfig) *QUICHandler {
	ctx, cancel := context.WithCancel(context.Background())
	return &QUICHandler{
		cfg:    cfg,
		ctx:    ctx,
		cancel: cancel,
		pool:   NewConnPool(0),
		serverConns: make(map[*quic.Conn]struct{}),
	}
}

// Start implements TunnelHandler.
func (h *QUICHandler) Start() error {
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
	h.useUDP = datagramEnabled() && h.cfg.QUICEnableUDP

	switch h.cfg.Mode {
	case "iran":
		return h.startIran()
	case "overseas":
		return h.startOverseas()
	default:
		return fmt.Errorf("unknown mode: %s", h.cfg.Mode)
	}
}

func (h *QUICHandler) startIran() error {
	ports, err := ParsePorts(h.cfg.LocalPorts)
	if err != nil {
		return fmt.Errorf("QUIC iran parse ports: %w", err)
	}
	h.mu.Lock()
	for _, port := range ports {
		l, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
		if err != nil {
			h.mu.Unlock()
			h.Stop()
			return fmt.Errorf("QUIC listen tcp port %d: %w", port, err)
		}
		h.tcpListeners = append(h.tcpListeners, l)
		go h.runIranTCPListener(l)

		if h.useUDP {
			pc, err := net.ListenPacket("udp", fmt.Sprintf(":%d", port))
			if err != nil {
				h.mu.Unlock()
				h.Stop()
				return fmt.Errorf("QUIC listen udp port %d: %w", port, err)
			}
			h.udpSockets = append(h.udpSockets, pc)
			go h.runIranUDPRelay(pc)
		}
	}
	h.mu.Unlock()

	system.LogInfo("QUIC Iran tunnel [%s] started on ports: %s (udp-datagrams: %v)", h.cfg.Name, h.cfg.LocalPorts, h.useUDP)
	return nil
}

func (h *QUICHandler) startOverseas() error {
	// ListenAddr owns its UDP socket and transport; closing the listener
	// releases both, unlike a manually created Transport with a borrowed socket.
	ln, err := quic.ListenAddr(fmt.Sprintf(":%d", h.cfg.RemotePort), serverTLSConfig(h.cert), &quic.Config{
		MaxIdleTimeout:       quicIdleTimeout,
		HandshakeIdleTimeout: quicHandshakeTO,
		KeepAlivePeriod:      10 * time.Second,
		// -1 disables incoming unidirectional streams (0 would select the
		// library default); this transport only opens bidirectional streams.
		MaxIncomingStreams:   maxSessionsPerTunnel,
		MaxIncomingUniStreams: -1,
		EnableDatagrams:      h.useUDP,
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
	h.dialMu.Unlock()
	system.LogInfo("QUIC tunnel [%s] stopped", h.cfg.Name)
}

// getSharedConn lazily dials (and redials) the single multiplexed QUIC
// connection to the overseas node.
func (h *QUICHandler) getSharedConn() (*quic.Conn, error) {
	h.dialMu.Lock()
	defer h.dialMu.Unlock()

	if h.clientConn != nil {
		select {
		case <-h.clientConn.Context().Done():
			h.clientConn = nil
		default:
			return h.clientConn, nil
		}
	}

	remoteAddr := net.JoinHostPort(h.cfg.RemoteIP, strconv.Itoa(h.cfg.RemotePort))
	dialCtx, cancel := context.WithTimeout(h.ctx, quicDialTimeout)
	defer cancel()

	conn, err := quic.DialAddr(dialCtx, remoteAddr, clientTLSConfig(h.cert, h.pin), &quic.Config{
		MaxIdleTimeout:       quicIdleTimeout,
		KeepAlivePeriod:      10 * time.Second,
		HandshakeIdleTimeout: quicHandshakeTO,
		EnableDatagrams:      h.useUDP,
	})
	if err != nil {
		return nil, fmt.Errorf("QUIC dial %s: %w", remoteAddr, err)
	}
	h.clientConn = conn
	return conn, nil
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
			ProxyBidirectionalContext(h.ctx, c, sc, func(in, out int64) {
				if config.GlobalConfig != nil {
					_ = config.GlobalConfig.UpdateTunnelStats(h.cfg.ID, in, out)
				}
			})
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

	dgState := qconn.ConnectionState().SupportsDatagrams
	if h.useUDP && dgState.Local && dgState.Remote {
		go h.runOverseasDatagrams(qconn)
	}

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
			targetAddr := fmt.Sprintf("127.0.0.1:%d", h.cfg.TargetPort)
			dialer := &net.Dialer{Timeout: 10 * time.Second}
			targetConn, err := dialer.DialContext(qconn.Context(), "tcp", targetAddr)
			h.pool.Release()
			if err != nil {
				system.LogError("QUIC Overseas connect to [%s]: %v", targetAddr, err)
				return
			}
			defer targetConn.Close()
			ProxyBidirectionalContext(qconn.Context(), c, targetConn, func(in, out int64) {
				if config.GlobalConfig != nil {
					_ = config.GlobalConfig.UpdateTunnelStats(h.cfg.ID, in, out)
				}
			})
		})
	}
}

// ──────────────────────────────────────────────────
// Experimental UDP relay over QUIC DATAGRAM (RFC 9221)
//
// Wire format of every datagram: [2-byte big-endian flow ID][payload]
// iran: maps local UDP endpoints to flow IDs and relays both directions.
// overseas: maps flow IDs to UDP "connections" toward 127.0.0.1:TargetPort.
// ──────────────────────────────────────────────────

type udpFlowEntry struct {
	local    net.Addr
	lastSeen time.Time
}

func (h *QUICHandler) runIranUDPRelay(pc net.PacketConn) {
	var mu sync.Mutex
	byAddr := make(map[string]uint16)
	byID := make(map[uint16]udpFlowEntry)
	var nextID uint16 = 1

	go func() {
		for {
			qconn, err := h.getSharedConn()
			if err != nil {
				select {
				case <-h.ctx.Done():
					return
				case <-time.After(time.Second):
					continue
				}
			}
			for {
				select {
				case <-h.ctx.Done():
					return
				case <-qconn.Context().Done():
					return
				default:
				}
				dgCtx, cancel := context.WithTimeout(h.ctx, 5*time.Second)
				data, err := qconn.ReceiveDatagram(dgCtx)
				cancel()
				if err != nil {
					if errors.Is(h.ctx.Err(), context.Canceled) {
						return
					}
					break // connection likely dead → outer loop redials
				}
				if len(data) < 3 {
					continue
				}
				id := binary.BigEndian.Uint16(data[:2])
				mu.Lock()
				entry, ok := byID[id]
				if ok {
					entry.lastSeen = time.Now()
					byID[id] = entry
				}
				mu.Unlock()
				if !ok {
					continue
				}
				_, _ = pc.WriteTo(data[2:], entry.local)
			}
		}
	}()

	buf := make([]byte, maxDatagramPayLen)
	for {
		_ = pc.SetReadDeadline(time.Now().Add(time.Second))
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				select {
				case <-h.ctx.Done():
					return
				default:
					h.expireFlows(&mu, byAddr, byID)
					continue
				}
			}
			return
		}
		if n == 0 {
			continue
		}
		key := addr.String()
		mu.Lock()
		id, ok := byAddr[key]
		if !ok {
			if len(byAddr) >= maxDatagramFlows {
				mu.Unlock()
				continue // flow table full — drop, document in README
			}
			id = nextID
			nextID++
			if nextID == 0 {
				nextID = 1
			}
			byAddr[key] = id
			byID[id] = udpFlowEntry{local: addr, lastSeen: time.Now()}
		} else {
			e := byID[id]
			e.lastSeen = time.Now()
			byID[id] = e
		}
		mu.Unlock()

		qconn, err := h.getSharedConn()
		if err != nil {
			continue
		}
		payload := make([]byte, 2+n)
		binary.BigEndian.PutUint16(payload[:2], id)
		copy(payload[2:], buf[:n])
		if err := qconn.SendDatagram(payload); err != nil {
			system.LogWarn("QUIC Iran send datagram: %v", err)
		}
	}
}

func (h *QUICHandler) expireFlows(mu *sync.Mutex, byAddr map[string]uint16, byID map[uint16]udpFlowEntry) {
	mu.Lock()
	defer mu.Unlock()
	now := time.Now()
	for id, e := range byID {
		if now.Sub(e.lastSeen) > datagramFlowTTL {
			delete(byAddr, e.local.String())
			delete(byID, id)
		}
	}
}

func (h *QUICHandler) runOverseasDatagrams(qconn *quic.Conn) {
	type flow struct {
		uc   *net.UDPConn
		stop context.CancelFunc
	}
	var mu sync.Mutex
	flows := make(map[uint16]*flow)
	defer func() {
		mu.Lock()
		for _, f := range flows {
			f.stop()
			_ = f.uc.Close()
		}
		mu.Unlock()
	}()

	targetAddr := fmt.Sprintf("127.0.0.1:%d", h.cfg.TargetPort)

	for {
		select {
		case <-h.ctx.Done():
			return
		case <-qconn.Context().Done():
			return
		default:
		}
		dgCtx, cancel := context.WithTimeout(h.ctx, 5*time.Second)
		data, err := qconn.ReceiveDatagram(dgCtx)
		cancel()
		if err != nil {
			if errors.Is(h.ctx.Err(), context.Canceled) || errors.Is(qconn.Context().Err(), context.Canceled) {
				return
			}
			if qconn.Context().Err() != nil {
				return
			}
			continue
		}
		if len(data) < 3 {
			continue
		}
		id := binary.BigEndian.Uint16(data[:2])

		mu.Lock()
		f, ok := flows[id]
		if !ok {
			if len(flows) >= maxDatagramFlows {
				mu.Unlock()
				continue
			}
			raddr, err := net.ResolveUDPAddr("udp", targetAddr)
			if err != nil {
				mu.Unlock()
				continue
			}
			uc, err := net.DialUDP("udp", nil, raddr)
			if err != nil {
				mu.Unlock()
				system.LogError("QUIC Overseas datagram dial target: %v", err)
				continue
			}
			fCtx, fCancel := context.WithCancel(h.ctx)
			f = &flow{uc: uc, stop: fCancel}
			flows[id] = f
			// Responses from the target flow back with the same flow ID.
			go func(id uint16, uc *net.UDPConn, fCtx context.Context) {
				buf := make([]byte, maxDatagramPayLen)
				for {
					_ = uc.SetReadDeadline(time.Now().Add(time.Second))
					n, err := uc.Read(buf)
					if err != nil {
						select {
						case <-fCtx.Done():
							return
						default:
							var netErr net.Error
							if errors.As(err, &netErr) && netErr.Timeout() {
								continue
							}
							return
						}
					}
					if n == 0 {
						continue
					}
					payload := make([]byte, 2+n)
					binary.BigEndian.PutUint16(payload[:2], id)
					copy(payload[2:], buf[:n])
					if err := qconn.SendDatagram(payload); err != nil {
						return
					}
				}
			}(id, uc, fCtx)
		}
		mu.Unlock()

		if _, err := f.uc.Write(data[2:]); err != nil {
			system.LogWarn("QUIC Overseas datagram write target: %v", err)
		}
	}
}
