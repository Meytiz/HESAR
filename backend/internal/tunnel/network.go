package tunnel

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/Meytiz/HESAR/backend/internal/config"
	"golang.org/x/net/proxy"
)

func dialTimeout(cfg *config.TunnelConfig) time.Duration {
	if cfg.DialTimeoutSeconds > 0 {
		return time.Duration(cfg.DialTimeoutSeconds) * time.Second
	}
	return 8 * time.Second
}
func idleTimeout(cfg *config.TunnelConfig) time.Duration {
	if cfg.IdleTimeoutSeconds > 0 {
		return time.Duration(cfg.IdleTimeoutSeconds) * time.Second
	}
	return 5 * time.Minute
}
func listenAddr(cfg *config.TunnelConfig, port int) string {
	return net.JoinHostPort(cfg.ListenAddress, strconv.Itoa(port))
}
func targetAddr(cfg *config.TunnelConfig) string {
	host := cfg.TargetHost
	if host == "" {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, strconv.Itoa(cfg.TargetPort))
}

// dialTCP routes DNS and connection setup through the selected SOCKS5 core.
// ContextDialer is mandatory: cancellation must also unblock SOCKS negotiation.
func dialTCP(ctx context.Context, cfg *config.TunnelConfig, addr string) (net.Conn, error) {
	d := &net.Dialer{Timeout: dialTimeout(cfg), KeepAlive: 30 * time.Second}
	if cfg.UnderlayInterface != "" {
		source, err := underlayAddress(ctx, cfg)
		if err != nil {
			return nil, err
		}
		d.LocalAddr = &net.TCPAddr{IP: source}
	}
	if cfg.ProxyURL == "" {
		return d.DialContext(ctx, "tcp", addr)
	}
	u, err := url.Parse(cfg.ProxyURL)
	if err != nil {
		return nil, fmt.Errorf("invalid SOCKS5 URL")
	}
	var auth *proxy.Auth
	if u.User != nil {
		password, _ := u.User.Password()
		auth = &proxy.Auth{User: u.User.Username(), Password: password}
	}
	p, err := proxy.SOCKS5("tcp", u.Host, auth, d)
	if err != nil {
		return nil, fmt.Errorf("SOCKS5 initialization failed")
	}
	cd, ok := p.(proxy.ContextDialer)
	if !ok {
		return nil, fmt.Errorf("SOCKS5 implementation lacks cancellation")
	}
	conn, err := cd.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("SOCKS5 connection failed: %w", err)
	}
	return conn, nil
}

// fragmentConn splits only the first plaintext TLS handshake record into
// valid TLS records. It makes no promise about TCP segmentation or DPI success.
// Application records, including encrypted TLS 1.3 handshakes, remain intact.
type fragmentConn struct {
	net.Conn
	ctx   context.Context
	size  int
	delay time.Duration
	mu    sync.Mutex
	first bool
}

func writeFull(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}

func (f *fragmentConn) Write(b []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.first || f.size == 0 || len(b) < 6 || b[0] != 22 || b[5] != 1 {
		return f.Conn.Write(b)
	}
	f.first = true
	n := int(binary.BigEndian.Uint16(b[3:5]))
	if n > len(b)-5 || n == 0 {
		return f.Conn.Write(b)
	}
	body := b[5 : 5+n]
	for len(body) > 0 {
		chunk := min(len(body), f.size)
		record := make([]byte, 5+chunk)
		copy(record[:3], b[:3])
		binary.BigEndian.PutUint16(record[3:5], uint16(chunk))
		copy(record[5:], body[:chunk])
		if err := writeFull(f.Conn, record); err != nil {
			return 0, err
		}
		body = body[chunk:]
		if len(body) > 0 && f.delay > 0 {
			timer := time.NewTimer(f.delay)
			select {
			case <-timer.C:
			case <-f.ctx.Done():
				timer.Stop()
				return 0, f.ctx.Err()
			}
		}
	}
	if err := writeFull(f.Conn, b[5+n:]); err != nil {
		return 0, err
	}
	return len(b), nil
}
