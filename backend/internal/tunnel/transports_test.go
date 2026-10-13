package tunnel

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Meytiz/HESAR/backend/internal/config"
)

func testPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return p
}
func testCertificate(t *testing.T) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		t.Fatal(err)
	}
	return
}
func testTarget(t *testing.T, serve func(net.Conn)) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); serve(c) }()
		}
	}()
	return l.Addr().(*net.TCPAddr).Port
}
func testPair(t *testing.T, protocol string, target int) (*config.TunnelConfig, *config.TunnelConfig) {
	t.Helper()
	cert, key := testCertificate(t)
	base := config.TunnelConfig{ID: "test", Name: "test", Protocol: protocol, EncryptionKey: strings.Repeat("a", 64), RemotePort: testPort(t),
		ListenAddress: "127.0.0.1", TargetPort: target, ServerName: "localhost", TLSCertFile: cert, TLSKeyFile: key, TLSCAFile: cert, DialTimeoutSeconds: 2}
	node := base
	node.Mode = "overseas"
	bridge := base
	bridge.ID = "bridge"
	bridge.Mode = "iran"
	bridge.RemoteIP = "127.0.0.1"
	bridge.LocalPorts = strconv.Itoa(testPort(t))
	return &bridge, &node
}
func startTestHandler(t *testing.T, cfg *config.TunnelConfig) TunnelHandler {
	t.Helper()
	h, err := newHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.Start(); err != nil {
		h.Stop()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		h.Stop()
		var pool *ConnPool
		switch h := h.(type) {
		case *TCPHandler:
			pool = h.pool
		case *KCPHandler:
			pool = h.pool
		case *QUICHandler:
			pool = h.pool
		case *AdaptiveHandler:
			pool = h.pool
		}
		deadline := time.Now().Add(2 * time.Second)
		for pool != nil {
			pool.mu.Lock()
			n := len(pool.sessions)
			pool.mu.Unlock()
			if n == 0 {
				return
			}
			if time.Now().After(deadline) {
				t.Errorf("handler leaked %d sessions after stop", n)
				return
			}
			time.Sleep(time.Millisecond)
		}
	})
	return h
}
func TestTransportRoundTrips(t *testing.T) {
	for _, protocol := range []string{"tcp", "kcp", "quic", "wss", "wss-shaped", "auto"} {
		t.Run(protocol, func(t *testing.T) {
			target := testTarget(t, func(c net.Conn) { _, _ = io.Copy(c, c) })
			bridge, node := testPair(t, protocol, target)
			startTestHandler(t, node)
			startTestHandler(t, bridge)
			c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", bridge.LocalPorts), time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(10 * time.Second))
			data := bytes.Repeat([]byte("payload-with-many-frames"), 20000)
			writeErr := make(chan error, 1)
			go func() { writeErr <- writeFull(c, data) }()
			got := make([]byte, len(data))
			if _, err := io.ReadFull(c, got); err != nil {
				t.Fatal(err)
			}
			if err := <-writeErr; err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(data, got) {
				t.Fatal("payload corrupted")
			}
		})
	}
}
func TestWSSFragmentedTLSAndHalfClose(t *testing.T) {
	target := testTarget(t, func(c net.Conn) { b, _ := io.ReadAll(c); _, _ = c.Write(append([]byte("response:"), b...)) })
	bridge, node := testPair(t, "wss", target)
	bridge.TLSFragmentSize = 128
	bridge.TLSFragmentDelayMS = 1
	startTestHandler(t, node)
	startTestHandler(t, bridge)
	c, err := net.DialTCP("tcp", nil, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: mustPort(t, bridge.LocalPorts)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(8 * time.Second))
	_, _ = c.Write([]byte("request"))
	_ = c.CloseWrite()
	got, err := io.ReadAll(c)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "response:request" {
		t.Fatalf("half-close discarded response: %q", got)
	}
}
func mustPort(t *testing.T, s string) int {
	t.Helper()
	p, err := strconv.Atoi(s)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func TestAutoFallsBackAndCoolsDown(t *testing.T) {
	target := testTarget(t, func(c net.Conn) { _, _ = io.Copy(c, c) })
	bridge, node := testPair(t, "auto", target)
	node.Protocol = "wss"
	bridge.DialTimeoutSeconds = 1
	startTestHandler(t, node)
	h := startTestHandler(t, bridge).(*AdaptiveHandler)
	c, err := h.dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	h.mu.Lock()
	retry := h.nextQUIC
	h.mu.Unlock()
	if !retry.After(time.Now()) {
		t.Fatal("failed UDP must enter cooldown")
	}
	c, err = h.dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	h.mu.Lock()
	same := h.nextQUIC.Equal(retry)
	h.mu.Unlock()
	if !same {
		t.Fatal("cooldown retried blocked UDP")
	}
}

func TestAutoUsesAuthenticatedQUICWhenAvailable(t *testing.T) {
	target := testTarget(t, func(c net.Conn) { _, _ = io.Copy(c, c) })
	bridge, node := testPair(t, "auto", target)
	startTestHandler(t, node)
	h := startTestHandler(t, bridge).(*AdaptiveHandler)
	c, err := h.dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, ok := c.(*quicStreamConn); !ok {
		t.Fatal("auto did not select authenticated QUIC")
	}
}
func TestWSSRejectsWrongKeyAndServerName(t *testing.T) {
	target := testTarget(t, func(c net.Conn) { _, _ = io.Copy(c, c) })
	bridge, node := testPair(t, "wss", target)
	startTestHandler(t, node)
	badKey := *bridge
	badKey.EncryptionKey = strings.Repeat("b", 64)
	badKey.WSPath = wsPath(node)
	if c, err := dialWSS(context.Background(), &badKey); err == nil {
		c.Close()
		t.Fatal("accepted wrong key")
	}
	badName := *bridge
	badName.ServerName = "wrong.example"
	if c, err := dialWSS(context.Background(), &badName); err == nil {
		c.Close()
		t.Fatal("accepted mismatching TLS hostname")
	}
}
func TestAutoSidecarNeverDialsDirect(t *testing.T) {
	bridge, _ := testPair(t, "auto", testPort(t))
	bridge.ProxyURL = "socks5://127.0.0.1:" + strconv.Itoa(testPort(t))
	h := NewAdaptiveHandler(bridge)
	h.quic = NewQUICHandler(bridge)
	defer h.Stop()
	_, err := h.dial(context.Background())
	if err == nil {
		t.Fatal("absent proxy accepted")
	}
	if !h.nextQUIC.IsZero() {
		t.Fatal("proxy configuration must skip direct QUIC")
	}
}
func TestSOCKS5DialCancellation(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	done := make(chan struct{})
	go func() {
		c, err := l.Accept()
		if err == nil {
			defer c.Close()
			_, _ = io.Copy(io.Discard, c)
		}
		close(done)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	cfg := &config.TunnelConfig{ProxyURL: "socks5://" + l.Addr().String(), DialTimeoutSeconds: 1}
	if c, err := dialTCP(ctx, cfg, "example.com:443"); err == nil {
		c.Close()
		t.Fatal("stalled SOCKS accepted")
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("SOCKS socket leaked after cancellation")
	}
}

type recordingConn struct {
	net.Conn
	bytes.Buffer
}

func (c *recordingConn) Read(b []byte) (int, error) { return 0, io.EOF }

func (c *recordingConn) Write(b []byte) (int, error) { return c.Buffer.Write(b) }
func TestTLSRecordFragmentationPreservesHandshake(t *testing.T) {
	raw := &recordingConn{}
	f := &fragmentConn{Conn: raw, ctx: context.Background(), size: 32}
	body := append([]byte{1}, bytes.Repeat([]byte{42}, 99)...)
	hello := append([]byte{22, 3, 1, 0, 100}, body...)
	if n, err := f.Write(hello); err != nil || n != len(hello) {
		t.Fatal(n, err)
	}
	var recovered []byte
	wire := raw.Bytes()
	records := 0
	for len(wire) > 0 {
		if len(wire) < 5 {
			t.Fatal("truncated record")
		}
		n := int(binary.BigEndian.Uint16(wire[3:5]))
		if n > 32 || len(wire) < 5+n {
			t.Fatal("invalid fragment")
		}
		recovered = append(recovered, wire[5:5+n]...)
		wire = wire[5+n:]
		records++
	}
	if !bytes.Equal(recovered, body) || records != 4 {
		t.Fatal("changed handshake contents")
	}
	raw.Reset()
	app := []byte{23, 3, 3, 0, 2, 1, 2}
	_, _ = f.Write(app)
	if !bytes.Equal(raw.Bytes(), app) {
		t.Fatal("fragmented application record")
	}
}
