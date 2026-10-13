package tunnel

import (
	"context"
	"fmt"
	"github.com/Meytiz/HESAR/backend/internal/config"
	"github.com/Meytiz/HESAR/backend/internal/provision"
	"github.com/Meytiz/HESAR/backend/internal/system"
	"time"
)

type managedCarrier struct {
	cfg          *config.TunnelConfig
	inner        TunnelHandler
	provisioned  bool
	cleanupError error
}

func (h *managedCarrier) Start() error {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	reply, err := provision.Call(ctx, "ensure", provision.Request{Tunnel: h.cfg})
	if err != nil {
		return err
	}
	h.provisioned = true
	if reply.Tunnel == nil {
		return fmt.Errorf("agent returned no effective transport")
	}
	inner, err := newTransportHandler(reply.Tunnel)
	if err != nil {
		return err
	}
	h.inner = inner
	return h.inner.Start()
}
func (h *managedCarrier) Stop() {
	h.cleanupError = nil
	if h.inner != nil {
		h.inner.Stop()
		h.inner = nil
	}
	if h.provisioned {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if _, err := provision.Call(ctx, "release", provision.Request{ID: h.cfg.ID}); err != nil {
			system.LogError("Managed carrier cleanup failed for %s: %v", h.cfg.ID, err)
			h.cleanupError = err
			return
		}
		h.provisioned = false
	}
}

func (h *managedCarrier) CleanupError() error { return h.cleanupError }
