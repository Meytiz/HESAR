package tunnel

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/Meytiz/HESAR/backend/internal/config"
	"github.com/Meytiz/HESAR/backend/internal/tunnel/crypto"
	"github.com/gorilla/websocket"
)

// The empty binary message is an explicit write-side EOF. It lets response
// traffic drain after the sender closes its local TCP write direction.
type websocketConn struct {
	ws                *websocket.Conn
	readMu, writeMu   sync.Mutex
	buffer            []byte
	readEOF, writeEOF bool
}

func wrapWebSocket(ws *websocket.Conn) *websocketConn {
	ws.SetReadLimit(crypto.MaxChunk + crypto.TagSize + 2)
	return &websocketConn{ws: ws}
}
func (c *websocketConn) Read(b []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if len(b) == 0 {
		return 0, nil
	}
	for len(c.buffer) == 0 {
		if c.readEOF {
			return 0, io.EOF
		}
		kind, payload, err := c.ws.ReadMessage()
		if err != nil {
			return 0, err
		}
		if kind != websocket.BinaryMessage {
			return 0, fmt.Errorf("non-binary tunnel frame")
		}
		if len(payload) == 0 {
			c.readEOF = true
			return 0, io.EOF
		}
		c.buffer = payload
	}
	n := copy(b, c.buffer)
	c.buffer = c.buffer[n:]
	return n, nil
}
func (c *websocketConn) Write(b []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.writeEOF {
		return 0, io.ErrClosedPipe
	}
	if len(b) == 0 {
		return 0, nil
	}
	if err := c.ws.WriteMessage(websocket.BinaryMessage, b); err != nil {
		return 0, err
	}
	return len(b), nil
}
func (c *websocketConn) CloseWrite() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.writeEOF {
		return nil
	}
	c.writeEOF = true
	return c.ws.WriteMessage(websocket.BinaryMessage, nil)
}
func (c *websocketConn) Close() error                  { return c.ws.Close() }
func (c *websocketConn) LocalAddr() net.Addr           { return c.ws.LocalAddr() }
func (c *websocketConn) RemoteAddr() net.Addr          { return c.ws.RemoteAddr() }
func (c *websocketConn) SetDeadline(t time.Time) error { return c.ws.UnderlyingConn().SetDeadline(t) }
func (c *websocketConn) SetReadDeadline(t time.Time) error {
	return c.ws.UnderlyingConn().SetReadDeadline(t)
}
func (c *websocketConn) SetWriteDeadline(t time.Time) error {
	return c.ws.UnderlyingConn().SetWriteDeadline(t)
}

func wsPath(cfg *config.TunnelConfig) string {
	if cfg.WSPath != "" {
		return cfg.WSPath
	}
	mac := hmac.New(sha256.New, []byte(cfg.EncryptionKey))
	_, _ = mac.Write([]byte("HESAR_WSS_PATH_v1"))
	return "/" + hex.EncodeToString(mac.Sum(nil)[:16])
}

func dialWSS(ctx context.Context, cfg *config.TunnelConfig) (net.Conn, error) {
	u := url.URL{Scheme: "wss", Host: net.JoinHostPort(cfg.ServerName, strconv.Itoa(cfg.RemotePort)), Path: wsPath(cfg)}
	d := websocket.Dialer{HandshakeTimeout: dialTimeout(cfg), ReadBufferSize: 32 * 1024, WriteBufferSize: 32 * 1024, Proxy: nil}
	d.NetDialTLSContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
		addr := net.JoinHostPort(cfg.RemoteIP, strconv.Itoa(cfg.RemotePort))
		raw, err := dialTCP(ctx, cfg, addr)
		if err != nil {
			return nil, err
		}
		stop := context.AfterFunc(ctx, func() { _ = raw.Close() })
		defer stop()
		tlsConfig := &tls.Config{ServerName: cfg.ServerName, MinVersion: tls.VersionTLS13, NextProtos: []string{"http/1.1"}}
		if cfg.TLSCAFile != "" || cfg.TLSCAPEM != "" {
			pem := []byte(cfg.TLSCAPEM)
			var err error
			if len(pem) == 0 {
				pem, err = os.ReadFile(cfg.TLSCAFile)
			}
			if err != nil {
				_ = raw.Close()
				return nil, fmt.Errorf("read TLS CA: %w", err)
			}
			roots, err := x509.SystemCertPool()
			if err != nil || roots == nil {
				roots = x509.NewCertPool()
			}
			if !roots.AppendCertsFromPEM(pem) {
				_ = raw.Close()
				return nil, fmt.Errorf("TLS CA contains no certificate")
			}
			tlsConfig.RootCAs = roots
		}
		_ = raw.SetDeadline(time.Now().Add(dialTimeout(cfg)))
		var transport net.Conn = raw
		if cfg.TLSFragmentSize > 0 {
			transport = &fragmentConn{Conn: raw, ctx: ctx, size: cfg.TLSFragmentSize, delay: time.Duration(cfg.TLSFragmentDelayMS) * time.Millisecond}
		}
		conn := tls.Client(transport, tlsConfig)
		if err := conn.HandshakeContext(ctx); err != nil {
			_ = raw.Close()
			return nil, fmt.Errorf("verified TLS handshake: %w", err)
		}
		return conn, nil
	}
	ws, resp, err := d.DialContext(ctx, u.String(), nil)
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	if err != nil {
		return nil, fmt.Errorf("WSS connection failed: %w", err)
	}
	c := shapeWSS(wrapWebSocket(ws), cfg.Protocol)
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stop()
	_ = c.SetDeadline(time.Now().Add(dialTimeout(cfg)))
	psk := sha256.Sum256([]byte(cfg.EncryptionKey))
	secure, err := crypto.NewSecureConn(c, psk[:], true)
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	// The node acknowledges authentication AND target readiness before the
	// bridge commits application bytes to this connection.
	var ack [1]byte
	if _, err := io.ReadFull(secure, ack[:]); err != nil || ack[0] != 0 {
		_ = secure.Close()
		return nil, fmt.Errorf("WSS target readiness failed")
	}
	_ = secure.SetDeadline(time.Time{})
	return secure, nil
}

// boundedListener limits even unauthenticated TLS/HTTP sockets, before
// net/http can allocate a goroutine per connection. Closing a hijacked
// WebSocket releases the same slot as closing an ordinary HTTP socket.
type boundedListener struct {
	net.Listener
	ctx   context.Context
	slots chan struct{}
}
type countedConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *countedConn) Close() error { err := c.Conn.Close(); c.once.Do(c.release); return err }
func (l *boundedListener) Accept() (net.Conn, error) {
	select {
	case l.slots <- struct{}{}:
	case <-l.ctx.Done():
		return nil, l.ctx.Err()
	}
	c, err := l.Listener.Accept()
	if err != nil {
		<-l.slots
		return nil, err
	}
	return &countedConn{Conn: c, release: func() { <-l.slots }}, nil
}

func (h *AdaptiveHandler) startWSSServer() error {
	var cert tls.Certificate
	var err error
	if h.cfg.TLSCertPEM != "" {
		cert, err = tls.X509KeyPair([]byte(h.cfg.TLSCertPEM), []byte(h.cfg.TLSKeyPEM))
	} else {
		cert, err = tls.LoadX509KeyPair(h.cfg.TLSCertFile, h.cfg.TLSKeyFile)
	}
	if err != nil {
		return fmt.Errorf("load WSS certificate: %w", err)
	}
	listener, err := net.Listen("tcp", listenAddr(h.cfg, h.cfg.RemotePort))
	if err != nil {
		return fmt.Errorf("WSS listen: %w", err)
	}
	limited := &boundedListener{Listener: listener, ctx: h.ctx, slots: make(chan struct{}, maxSessionsPerTunnel)}
	tlsListener := tls.NewListener(limited, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13, NextProtos: []string{"http/1.1"}})
	upgrader := websocket.Upgrader{HandshakeTimeout: dialTimeout(h.cfg), ReadBufferSize: 32 * 1024, WriteBufferSize: 32 * 1024}
	h.server = &http.Server{ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 * 1024,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Content-Type-Options", "nosniff")
			if r.Method != http.MethodGet || r.URL.Path != wsPath(h.cfg) || !websocket.IsWebSocketUpgrade(r) {
				if r.URL.Path != "/" {
					http.NotFound(w, r)
					return
				}
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				_, _ = io.WriteString(w, "<!doctype html><html><head><title>Welcome</title></head><body><h1>Welcome</h1><p>The service is available.</p></body></html>")
				return
			}
			ws, err := upgrader.Upgrade(w, r, nil)
			if err != nil {
				return
			}
			c := shapeWSS(wrapWebSocket(ws), h.cfg.Protocol)
			h.pool.Run(c, func(c net.Conn) {
				if err := h.pool.Acquire(h.ctx); err != nil {
					return
				}
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(dialTimeout(h.cfg)))
				psk := sha256.Sum256([]byte(h.cfg.EncryptionKey))
				secure, err := crypto.NewSecureConn(c, psk[:], false)
				if err != nil {
					h.pool.Release()
					return
				}
				defer secure.Close()
				dialCtx, cancel := context.WithTimeout(h.ctx, dialTimeout(h.cfg))
				target, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", targetAddr(h.cfg))
				cancel()
				h.pool.Release()
				if err != nil {
					return
				}
				defer target.Close()
				if _, err := secure.Write([]byte{0}); err != nil {
					return
				}
				_ = c.SetDeadline(time.Time{})
				proxyWithTimeout(h.ctx, secure, target, h.onBytes, idleTimeout(h.cfg))
			})
		}),
	}
	h.wssListener = tlsListener
	go func() { _ = h.server.Serve(tlsListener) }()
	return nil
}
