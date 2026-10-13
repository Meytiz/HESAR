package tunnel

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Meytiz/HESAR/backend/internal/config"
)

func waitDone(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("worker did not terminate")
	}
}

func TestMutualTLSConfiguration(t *testing.T) {
	cert, pin, err := DeriveQUICCert([]byte("test credential only"))
	if err != nil {
		t.Fatal(err)
	}
	server := serverTLSConfig(cert)
	client := clientTLSConfig(cert, pin)
	if server.ClientAuth != tls.RequireAnyClientCert || server.MinVersion != tls.VersionTLS13 {
		t.Fatal("mutual TLS must be required")
	}
	if len(client.Certificates) != 1 || server.VerifyPeerCertificate == nil {
		t.Fatal("both peers must supply and verify credentials")
	}
	if err := server.VerifyPeerCertificate(cert.Certificate, nil); err != nil {
		t.Fatal(err)
	}
	if err := server.VerifyPeerCertificate(nil, nil); err == nil {
		t.Fatal("missing certificate accepted")
	}
	other, _, err := DeriveQUICCert([]byte("different test credential"))
	if err != nil {
		t.Fatal(err)
	}
	if err := server.VerifyPeerCertificate(other.Certificate, nil); err == nil {
		t.Fatal("wrong credential accepted")
	}
	if err := client.VerifyPeerCertificate(other.Certificate, nil); err == nil {
		t.Fatal("wrong server credential accepted")
	}
}

func TestMutualTLSHandshake(t *testing.T) {
	cert, pin, err := DeriveQUICCert([]byte("local handshake test"))
	if err != nil {
		t.Fatal(err)
	}
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	server := tls.Server(a, serverTLSConfig(cert))
	client := tls.Client(b, clientTLSConfig(cert, pin))
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- server.HandshakeContext(ctx) }()
	if err := client.HandshakeContext(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}

func TestPoolAdmissionAndStop(t *testing.T) {
	p := NewConnPool(1)
	defer p.CloseAll()
	release := make(chan struct{})
	defer close(release)
	for i := 0; i < maxSessionsPerTunnel; i++ {
		a, b := net.Pipe()
		defer b.Close()
		if !p.Run(a, func(net.Conn) { <-release }) {
			t.Fatal("unexpected rejection")
		}
	}
	a, b := net.Pipe()
	defer b.Close()
	if p.Run(a, func(net.Conn) {}) {
		t.Fatal("capacity exceeded")
	}
	p.CloseAll()
	a, b = net.Pipe()
	defer b.Close()
	if p.Run(a, func(net.Conn) {}) {
		t.Fatal("stopped pool admitted session")
	}
}

func TestPoolCancellationAndEnvironment(t *testing.T) {
	t.Setenv(envMaxConcurrentHandshakes, "23")
	p := NewConnPool(0)
	if p.Cap() != 23 {
		t.Fatal("environment override ignored")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if p.Acquire(ctx) == nil || p.InUse() != 0 {
		t.Fatal("canceled acquire consumed a slot")
	}
}

func TestProxyCancellation(t *testing.T) {
	a, client := net.Pipe()
	b, target := net.Pipe()
	defer client.Close()
	defer target.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		ProxyBidirectionalContext(ctx, a, b, nil)
		close(done)
	}()
	cancel()
	waitDone(t, done)
}

func TestProxyOneWayActivity(t *testing.T) {
	a, client := net.Pipe()
	b, target := net.Pipe()
	defer client.Close()
	defer target.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		proxyWithTimeout(ctx, a, b, nil, 500*time.Millisecond)
		close(done)
	}()
	readDone := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, target)
		close(readDone)
	}()
	for i := 0; i < 15; i++ {
		_ = client.SetWriteDeadline(time.Now().Add(time.Second))
		if _, err := client.Write([]byte("data")); err != nil {
			t.Fatalf("active one-way connection closed: %v", err)
		}
		time.Sleep(60 * time.Millisecond)
	}
	cancel()
	waitDone(t, done)
	waitDone(t, readDone)
}

func TestProxyBlockedWriteTerminates(t *testing.T) {
	a, client := net.Pipe()
	b, target := net.Pipe()
	defer client.Close()
	defer target.Close()
	done := make(chan struct{})
	go func() {
		proxyWithTimeout(context.Background(), a, b, nil, 100*time.Millisecond)
		close(done)
	}()
	_ = client.SetWriteDeadline(time.Now().Add(time.Second))
	if _, err := client.Write([]byte("unread data")); err != nil {
		t.Fatal(err)
	}
	waitDone(t, done)
}

func TestUDPDisabledBeforeListen(t *testing.T) {
	h := NewQUICHandler(&config.TunnelConfig{QUICEnableUDP: true})
	defer h.Stop()
	if err := h.Start(); err == nil || !strings.Contains(err.Error(), "disabled") {
		t.Fatal("experimental UDP must fail closed")
	}
}
