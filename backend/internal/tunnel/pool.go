package tunnel

import (
	"context"
	"net"
	"os"
	"strconv"
	"sync"
	"time"
)

const DefaultMaxConcurrentHandshakes = 10
const envMaxConcurrentHandshakes = "HESAR_MAX_CONCURRENT_HANDSHAKES"
const maxSessionsPerTunnel = 256

// ConnPool bounds both setup concurrency and accepted sessions (including
// queued sessions). Admission occurs before spawning a worker goroutine.
type ConnPool struct {
	sem      chan struct{}
	mu       sync.Mutex
	sessions map[net.Conn]struct{}
	stopped  bool
}

func NewConnPool(size int) *ConnPool {
	if size <= 0 {
		size = DefaultMaxConcurrentHandshakes
		if n, err := strconv.Atoi(os.Getenv(envMaxConcurrentHandshakes)); err == nil && n > 0 && n <= maxSessionsPerTunnel {
			size = n
		}
	}
	return &ConnPool{sem: make(chan struct{}, size), sessions: make(map[net.Conn]struct{})}
}

// Run rejects excess sessions immediately; no unbounded goroutine backlog.
func (p *ConnPool) Run(c net.Conn, serve func(net.Conn)) bool {
	p.mu.Lock()
	if p.stopped || len(p.sessions) >= maxSessionsPerTunnel {
		p.mu.Unlock()
		_ = c.Close()
		return false
	}
	p.sessions[c] = struct{}{}
	p.mu.Unlock()
	go func() {
		defer func() {
			_ = c.Close()
			p.mu.Lock()
			delete(p.sessions, c)
			p.mu.Unlock()
		}()
		serve(c)
	}()
	return true
}

// CloseAll closes raw accepted connections, unblocking pending reads/writes.
// Once stopped, a pool never admits another session.
func (p *ConnPool) CloseAll() {
	p.mu.Lock()
	p.stopped = true
	for c := range p.sessions {
		_ = c.Close()
	}
	p.mu.Unlock()
}

func (p *ConnPool) Acquire(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case p.sem <- struct{}{}:
		if err := ctx.Err(); err != nil {
			p.Release()
			return err
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (p *ConnPool) Release()   { <-p.sem }
func (p *ConnPool) InUse() int { return len(p.sem) }
func (p *ConnPool) Cap() int   { return cap(p.sem) }
