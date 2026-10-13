package tunnel

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Meytiz/HESAR/backend/internal/config"
)

var bufferPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 32*1024)
		return &b
	},
}

const MaxPortsPerTunnel = config.MaxPortsPerTunnel

func ParsePorts(portsStr string) ([]int, error) { return config.ParsePorts(portsStr) }

func copyWithActivity(ctx context.Context, dst, src net.Conn, timeout time.Duration, activity *atomic.Int64) (int64, error) {
	bufp := bufferPool.Get().(*[]byte)
	defer bufferPool.Put(bufp)
	var written int64
	for {
		if err := ctx.Err(); err != nil {
			return written, err
		}
		nr, er := src.Read(*bufp)
		if nr > 0 {
			activity.Store(time.Now().UnixNano())
			_ = dst.SetWriteDeadline(time.Now().Add(timeout))
			if err := ctx.Err(); err != nil {
				return written, err
			}
			nw, ew := dst.Write((*bufp)[:nr])
			written += int64(nw)
			if ew != nil {
				return written, ew
			}
			if nw != nr {
				return written, io.ErrShortWrite
			}
			activity.Store(time.Now().UnixNano())
		}
		if er != nil {
			return written, er
		}
	}
}

// closeWriter is satisfied by *net.TCPConn, *tls.Conn, crypto.SecureConn and
// quicStreamConn. Half-closing the write side (instead of dropping the whole
// connection) is what lets the peer's Read observe EOF promptly.
type closeWriter interface {
	CloseWrite() error
}

// halfCloseWrite shuts down only the write direction of c when the concrete
// connection supports it. A previous version type-asserted *net.TCPConn only,
// so QUIC streams and TLS connections never half-closed: the peer's proxy
// goroutine then blocked until copyWithIdleTimeout's 5-minute read deadline
// expired, pinning two goroutines, two conns and (on the QUIC side) a stream
// slot for 5 minutes after every ordinary request/response exchange.
func halfCloseWrite(c net.Conn) {
	if cw, ok := c.(closeWriter); ok {
		_ = cw.CloseWrite()
	}
}

// ProxyBidirectional pumps bytes in both directions until either side ends,
// then half-closes the peer's write side so the other direction can observe
// EOF and unwind promptly, and finally closes both connections.
func ProxyBidirectional(c1, c2 net.Conn, onBytes func(in, out int64)) {
	ProxyBidirectionalContext(context.Background(), c1, c2, onBytes)
}

// Cancellation closes the underlying connections to reliably unblock I/O.
// SecureConn.Close must therefore remain safe concurrently with Read.
func ProxyBidirectionalContext(parent context.Context, c1, c2 net.Conn, onBytes func(in, out int64)) {
	proxyWithTimeout(parent, c1, c2, onBytes, 5*time.Minute)
}

func proxyWithTimeout(parent context.Context, c1, c2 net.Conn, onBytes func(in, out int64), timeout time.Duration) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	var activity atomic.Int64
	activity.Store(time.Now().UnixNano())
	_ = c1.SetReadDeadline(time.Time{})
	_ = c2.SetReadDeadline(time.Time{})
	// Cancel on whole-session inactivity instead of retrying a framed Read
	// after a deadline (which could have consumed part of a frame).
	watchDone := make(chan struct{})
	defer close(watchDone)
	go func() {
		ticker := time.NewTicker(timeout / 4)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-watchDone:
				return
			case <-ticker.C:
				if time.Since(time.Unix(0, activity.Load())) >= timeout {
					cancel()
					return
				}
			}
		}
	}()
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		_ = c1.Close()
		_ = c2.Close()
		close(done)
	})
	var wg sync.WaitGroup
	wg.Add(2)
	pump := func(dst, src net.Conn, inbound bool) {
		defer wg.Done()
		n, err := copyWithActivity(ctx, dst, src, timeout, &activity)
		if errors.Is(err, io.EOF) {
			halfCloseWrite(dst)
		} else {
			cancel()
		}
		if onBytes != nil {
			if inbound {
				onBytes(n, 0)
			} else {
				onBytes(0, n)
			}
		}
	}
	go pump(c1, c2, true)
	go pump(c2, c1, false)
	wg.Wait()
	if !stop() {
		<-done
	}
	_ = c1.Close()
	_ = c2.Close()
}
