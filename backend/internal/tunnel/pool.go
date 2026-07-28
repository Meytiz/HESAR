package tunnel

import (
	"context"
	"os"
	"strconv"
)

// DefaultMaxConcurrentHandshakes is the default number of connections that
// may be *established* (outbound Dial + secure handshake) at the same time,
// per tunnel instance.
//
// Background
// ----------
// Every listener in this package (TCP, KCP, SNI-Spoof, IP-Spoof) used to do
// this on every single Accept():
//
//     go func(c net.Conn) {
//         remoteConn, _ := net.DialTimeout(...)      // outbound dial
//         secureConn, _ := crypto.NewSecureConn(...) // X25519 + ChaCha20 handshake
//         ProxyBidirectional(...)
//     }(clientConn)
//
// i.e. an *unbounded* number of goroutines could be spawned instantly, each
// immediately opening a brand-new outbound TCP/KCP socket and performing a
// full asymmetric key-exchange + AEAD handshake. Under normal load this is
// fine, but:
//
//   - A burst of incoming connections (many parallel xray/VLESS/VMess
//     sub-connections, a client reconnect storm, or a deliberate flood)
//     causes an equally large burst of *simultaneous* outbound dials and
//     crypto handshakes, spiking CPU/FD/socket usage with no back-pressure.
//   - That burst is also an easy DPI / traffic-fingerprinting signal — a
//     restricted-network firewall can flag a host that suddenly opens many
//     parallel connections to the same overseas IP at once.
//   - There was no limit at all: resource usage was bounded only by the OS
//     (file descriptors, ephemeral ports, memory).
//
// The fix implemented in this file is a small, dependency-free "worker
// pool": a buffered channel used as a semaphore that bounds how many
// dial+handshake operations may be *in flight* at once (default: 10),
// while Accept() itself is never blocked and extra connections simply
// queue asynchronously until a slot frees up. As soon as a connection's
// handshake succeeds, its slot is released immediately — *before* the
// (potentially long-lived) bidirectional proxy loop starts — so already
// established tunnel sessions are never limited in number or throughput;
// only the *rate of new connection setups* is capped.
const DefaultMaxConcurrentHandshakes = 10

// envMaxConcurrentHandshakes lets an operator override the pool size
// without recompiling, e.g.:
//
//	HESAR_MAX_CONCURRENT_HANDSHAKES=25 ./hesar -config data/config.json
const envMaxConcurrentHandshakes = "HESAR_MAX_CONCURRENT_HANDSHAKES"

// ConnPool is a bounded, async worker pool used to throttle concurrent
// connection-establishment work (outbound Dial + secure handshake).
//
// Go multiplexes goroutines onto OS threads automatically, so the
// "thread-pool" behaviour requested is implemented the idiomatic Go way: a
// fixed-size semaphore built from a buffered channel. This gives the same
// guarantee a classic thread pool gives — at most N units of work run
// concurrently, everything else queues asynchronously with zero
// busy-waiting — without fighting Go's scheduler.
type ConnPool struct {
	sem chan struct{}
}

// NewConnPool creates a pool that allows at most size concurrent
// Acquire()-ed slots. If size <= 0, DefaultMaxConcurrentHandshakes (10) is
// used, unless overridden by the HESAR_MAX_CONCURRENT_HANDSHAKES env var.
func NewConnPool(size int) *ConnPool {
	if size <= 0 {
		size = DefaultMaxConcurrentHandshakes
		if v := os.Getenv(envMaxConcurrentHandshakes); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				size = n
			}
		}
	}
	return &ConnPool{sem: make(chan struct{}, size)}
}

// Acquire waits (from the caller's goroutine — it never blocks the
// Accept() loop, since it is always invoked from inside a freshly spawned
// goroutine) until a pool slot is free, or ctx is cancelled (e.g. the
// tunnel is being stopped).
func (p *ConnPool) Acquire(ctx context.Context) error {
	select {
	case p.sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Release frees a previously Acquire()-ed slot. Safe to call at most once
// per successful Acquire call (handlers guard this with a small
// "released" flag — see tcp.go/kcp.go/sni.go/spoof.go).
func (p *ConnPool) Release() {
	<-p.sem
}

// InUse returns how many slots are currently taken (handy for
// metrics/logging/dashboard widgets).
func (p *ConnPool) InUse() int {
	return len(p.sem)
}

// Cap returns the configured pool size.
func (p *ConnPool) Cap() int {
	return cap(p.sem)
}
