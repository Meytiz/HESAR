package tunnel

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/Meytiz/HESAR/backend/internal/config"
	"github.com/Meytiz/HESAR/backend/internal/system"
	"github.com/quic-go/quic-go"
)

// AdaptiveHandler uses native authenticated QUIC and verified HTTPS/WSS.
// Selection happens before any application payload is read. Established
// sessions are never replayed or migrated across transports.
type AdaptiveHandler struct {
	cfg         *config.TunnelConfig
	ctx         context.Context
	cancel      context.CancelFunc
	pool        *ConnPool
	quic        *QUICHandler
	listeners   []net.Listener
	wssListener net.Listener
	server      *http.Server
	mu          sync.Mutex
	nextQUIC    time.Time
	selectionMu sync.Mutex
}

func NewAdaptiveHandler(cfg *config.TunnelConfig) *AdaptiveHandler {
	ctx, cancel := context.WithCancel(context.Background())
	return &AdaptiveHandler{cfg: cfg, ctx: ctx, cancel: cancel, pool: NewConnPool(0)}
}
func (h *AdaptiveHandler) Start() error {
	if h.cfg.Protocol == ProtocolAuto {
		h.quic = NewQUICHandler(h.cfg)
		if err := h.quic.prepare(); err != nil {
			return err
		}
	}
	if h.cfg.Mode == "overseas" {
		if err := h.startWSSServer(); err != nil {
			return err
		}
		if h.quic != nil {
			if err := h.quic.startOverseas(); err != nil {
				h.Stop()
				return err
			}
		}
	} else {
		ports, err := ParsePorts(h.cfg.LocalPorts)
		if err != nil {
			return err
		}
		for _, port := range ports {
			l, err := net.Listen("tcp", listenAddr(h.cfg, port))
			if err != nil {
				h.Stop()
				return err
			}
			h.listeners = append(h.listeners, l)
			go h.serveLocal(l)
		}
	}
	system.LogInfo("%s tunnel [%s] started", h.cfg.Protocol, h.cfg.Name)
	return nil
}
func (h *AdaptiveHandler) Stop() {
	h.cancel()
	for _, l := range h.listeners {
		_ = l.Close()
	}
	if h.wssListener != nil {
		_ = h.wssListener.Close()
	}
	if h.server != nil {
		_ = h.server.Close()
	}
	h.pool.CloseAll()
	if h.quic != nil {
		h.quic.Stop()
	}
}
func (h *AdaptiveHandler) onBytes(in, out int64) {
	if config.GlobalConfig != nil {
		_ = config.GlobalConfig.UpdateTunnelStats(h.cfg.ID, in, out)
	}
}
func (h *AdaptiveHandler) dial(ctx context.Context) (net.Conn, error) {
	// A configured sidecar must carry ALL outbound data. Never bypass it
	// with a direct QUIC connection when it is unavailable.
	if h.quic != nil && h.cfg.ProxyURL == "" {
		h.selectionMu.Lock()
		h.mu.Lock()
		eligible := !time.Now().Before(h.nextQUIC)
		h.mu.Unlock()
		if eligible {
			qconn, err := h.quic.getSharedConn()
			if err != nil {
				h.markQUICFailure()
			}
			h.selectionMu.Unlock()
			if err == nil {
				c, err := h.quic.openStream(ctx, qconn)
				if err == nil {
					return c, nil
				}
				h.markQUICFailure()
			}
		} else {
			h.selectionMu.Unlock()
		}
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// QUIC and WSS have separate setup budgets: QUIC timeout must leave
	// time for fallback. Parent cancellation still aborts both immediately.
	wssCtx, cancel := context.WithTimeout(ctx, dialTimeout(h.cfg))
	defer cancel()
	return dialWSS(wssCtx, h.cfg)
}
func (h *AdaptiveHandler) markQUICFailure() {
	cooldown := 60 * time.Second
	if h.cfg.FallbackCooldownSeconds > 0 {
		cooldown = time.Duration(h.cfg.FallbackCooldownSeconds) * time.Second
	}
	h.mu.Lock()
	h.nextQUIC = time.Now().Add(cooldown)
	h.mu.Unlock()
	system.LogWarn("Adaptive tunnel [%s]: QUIC setup failed; trying HTTPS, retry QUIC after %s", h.cfg.Name, cooldown)
}

func (h *AdaptiveHandler) serveLocal(l net.Listener) {
	for {
		c, err := l.Accept()
		if err != nil {
			if h.ctx.Err() != nil {
				return
			}
			system.LogWarn("Adaptive accept: %v", err)
			return
		}
		h.pool.Run(c, func(c net.Conn) {
			if err := h.pool.Acquire(h.ctx); err != nil {
				return
			}
			remote, err := h.dial(h.ctx)
			h.pool.Release()
			if err != nil {
				system.LogWarn("Tunnel [%s] setup failed: %v", h.cfg.Name, err)
				return
			}
			defer remote.Close()
			proxyWithTimeout(h.ctx, c, remote, h.onBytes, idleTimeout(h.cfg))
		})
	}
}

func (h *QUICHandler) openStream(ctx context.Context, qconn *quic.Conn) (net.Conn, error) {
	setupCtx, cancel := context.WithTimeout(ctx, dialTimeout(h.cfg))
	defer cancel()
	s, err := qconn.OpenStreamSync(setupCtx)
	if err != nil {
		return nil, err
	}
	c := &quicStreamConn{s: s, laddr: qconn.LocalAddr(), raddr: qconn.RemoteAddr()}
	if h.cfg.Protocol == ProtocolAuto {
		stop := context.AfterFunc(setupCtx, func() { _ = c.Close() })
		defer stop()
		_ = c.SetDeadline(time.Now().Add(dialTimeout(h.cfg)))
		if _, err := c.Write([]byte{1}); err != nil {
			_ = c.Close()
			return nil, err
		}
		var ack [1]byte
		if _, err := io.ReadFull(c, ack[:]); err != nil || ack[0] != 0 {
			_ = c.Close()
			return nil, fmt.Errorf("QUIC target readiness failed")
		}
		_ = c.SetDeadline(time.Time{})
	}
	return c, nil
}
