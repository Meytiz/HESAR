package crypto

import (
	"bytes"
	"net"
	"sync"
	"testing"
	"time"
)

// handshakePair wires a client and server SecureConn over an in-memory
// net.Pipe and returns them once BOTH handshakes have completed.
func handshakePair(t *testing.T, clientPSK, serverPSK []byte) (*SecureConn, *SecureConn, error) {
	t.Helper()
	a, b := net.Pipe()

	// net.Pipe is unbuffered and has no OS-level timeouts: a peer that
	// aborts mid-handshake (e.g. MAC verification failure) would otherwise
	// leave the other side blocked in ReadFull forever. Bound the whole
	// handshake so failure paths surface as deadline errors instead of
	// hanging the test binary.
	deadline := time.Now().Add(5 * time.Second)
	_ = a.SetDeadline(deadline)
	_ = b.SetDeadline(deadline)

	var (
		wg      sync.WaitGroup
		client  *SecureConn
		server  *SecureConn
		clientE error
		serverE error
	)
	wg.Add(2)
	go func() {
		defer wg.Done()
		client, clientE = NewSecureConn(a, clientPSK, true)
	}()
	go func() {
		defer wg.Done()
		server, serverE = NewSecureConn(b, serverPSK, false)
	}()
	wg.Wait()

	if clientE != nil || serverE != nil {
		if clientE == nil {
			_ = client.Close()
		}
		if serverE == nil {
			_ = server.Close()
		}
		_ = a.Close()
		_ = b.Close()
		return nil, nil, coalesceErr(clientE, serverE)
	}

	_ = a.SetDeadline(time.Time{})
	_ = b.SetDeadline(time.Time{})
	return client, server, nil
}

func coalesceErr(a, b error) error {
	if a != nil {
		return a
	}
	return b
}

func TestSecureConnRoundTrip(t *testing.T) {
	psk := make([]byte, 32)
	for i := range psk {
		psk[i] = byte(i)
	}

	client, server, err := handshakePair(t, psk, psk)
	if err != nil {
		t.Fatalf("handshake failed: %v", err)
	}
	defer client.Close()
	defer server.Close()

	payload := bytes.Repeat([]byte("HESAR vNext quic-first "), 4000) // > MaxChunk, forces chunking
	errCh := make(chan error, 1)
	go func() {
		buf := make([]byte, len(payload))
		read := 0
		for read < len(buf) {
			n, err := server.Read(buf[read:])
			if err != nil {
				errCh <- err
				return
			}
			read += n
		}
		if !bytes.Equal(buf, payload) {
			errCh <- net.ErrClosed // any non-nil sentinel; equality is what matters
			return
		}
		errCh <- nil
	}()

	if _, err := client.Write(payload); err != nil {
		t.Fatalf("client write: %v", err)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("server-side round trip failed: %v", err)
	}
}

func TestSecureConnRejectsWrongPSK(t *testing.T) {
	clientPSK := make([]byte, 32)
	serverPSK := make([]byte, 32)
	serverPSK[0] = 0xFF

	_, _, err := handshakePair(t, clientPSK, serverPSK)
	if err == nil {
		t.Fatal("handshake with mismatched PSKs must fail")
	}
}

func TestSecureConnConcurrentWriters(t *testing.T) {
	// Regression test for the write-path race: concurrent Write calls must
	// not corrupt the stream (serialised via writeMu, single write per frame).
	psk := make([]byte, 32)
	client, server, err := handshakePair(t, psk, psk)
	if err != nil {
		t.Fatalf("handshake failed: %v", err)
	}
	defer client.Close()
	defer server.Close()

	const writers = 8
	const perWriter = 200
	msg := bytes.Repeat([]byte("x"), 512)

	go func() {
		var wg sync.WaitGroup
		for w := 0; w < writers; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := 0; i < perWriter; i++ {
					_, _ = client.Write(msg) // err surfaces as read failure below
				}
			}()
		}
		wg.Wait()
		_ = client.Close()
	}()

	total := writers * perWriter * len(msg)
	got := 0
	buf := make([]byte, 4096)
	for got < total {
		n, err := server.Read(buf)
		got += n
		if err != nil {
			break
		}
	}
	if got != total {
		t.Fatalf("stream corrupted under concurrent writers: got %d bytes, want %d", got, total)
	}
}

func TestGenerateRandomHexKey(t *testing.T) {
	k, err := GenerateRandomHexKey(32)
	if err != nil {
		t.Fatalf("GenerateRandomHexKey: %v", err)
	}
	if len(k) != 64 {
		t.Fatalf("expected 64 hex chars, got %d", len(k))
	}
	k2, err := GenerateRandomHexKey(32)
	if err != nil {
		t.Fatalf("GenerateRandomHexKey (2nd): %v", err)
	}
	if k == k2 {
		t.Fatal("two random keys must not collide")
	}
}
