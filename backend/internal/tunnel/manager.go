package tunnel

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"time"

	"github.com/Meytiz/HESAR/backend/internal/config"
	"github.com/Meytiz/HESAR/backend/internal/provision"
	"github.com/Meytiz/HESAR/backend/internal/system"
)

// TunnelHandler is the lifecycle contract every transport implements.
type TunnelHandler interface {
	Start() error
	Stop()
}

// CentralManager owns the set of running tunnels.
//
// Lifecycle operations are serialized through completion, including status
// persistence. Start only binds local listeners; network dialing is lazy.
type CentralManager struct {
	mu       sync.Mutex
	handlers map[string]TunnelHandler
}

// GlobalTunnelManager is the process-wide tunnel registry.
var GlobalTunnelManager = &CentralManager{
	handlers: make(map[string]TunnelHandler),
}

// Protocol identifiers accepted by the vNext manager. "sni_spoof",
// "ip_spoof" and the TLS-over-TCP fallback were intentionally REMOVED —
// tunnels with those protocols get an explicit migration error instead
// of silently misbehaving.
const (
	ProtocolTCP  = "tcp"
	ProtocolKCP  = "kcp"
	ProtocolQUIC = "quic"
	ProtocolWSS  = "wss"
	ProtocolAuto = "auto"
)

func newHandler(cfg *config.TunnelConfig) (TunnelHandler, error) {
	if cfg.Carrier != "" && cfg.Carrier != "direct" || provision.SocketAvailable() {
		return &managedCarrier{cfg: cfg}, nil
	}
	return newTransportHandler(cfg)
}

func newTransportHandler(cfg *config.TunnelConfig) (TunnelHandler, error) {
	switch cfg.Protocol {
	case ProtocolTCP:
		return NewTCPHandler(cfg), nil
	case ProtocolKCP:
		return NewKCPHandler(cfg), nil
	case ProtocolQUIC:
		return NewQUICHandler(cfg), nil
	case ProtocolWSS, "wss-shaped", ProtocolAuto:
		return NewAdaptiveHandler(cfg), nil
	case "tls", "sni_spoof", "ip_spoof":
		return nil, fmt.Errorf("protocol %q has been REMOVED in HESAR vNext (use 'quic', 'tcp' or 'kcp')", cfg.Protocol)
	default:
		return nil, fmt.Errorf("unsupported protocol: %s", cfg.Protocol)
	}
}

// StartTunnel serializes start/restart against stop and shutdown.
func (m *CentralManager) StartTunnel(cfg *config.TunnelConfig) error {
	if err := config.ValidateTunnel(cfg); err != nil {
		return err
	}
	handler, err := newHandler(cfg)
	if err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if existing, ok := m.handlers[cfg.ID]; ok {
		existing.Stop()
		delete(m.handlers, cfg.ID)
	}
	if err := handler.Start(); err != nil {
		handler.Stop()
		if config.GlobalConfig != nil {
			_ = config.GlobalConfig.UpdateTunnelStatus(cfg.ID, "inactive")
		}
		return err
	}
	m.handlers[cfg.ID] = handler

	if config.GlobalConfig != nil {
		if err := config.GlobalConfig.UpdateTunnelStatus(cfg.ID, "active"); err != nil {
			handler.Stop()
			delete(m.handlers, cfg.ID)
			return fmt.Errorf("persist active status: %w", err)
		}
	}
	return nil
}

// StopTunnel stops a running tunnel.
func (m *CentralManager) StopTunnel(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	handler, exists := m.handlers[id]
	if !exists {
		if config.GlobalConfig != nil {
			cfg, err := config.GlobalConfig.GetTunnel(id)
			if err != nil {
				return err
			}
			if runtime.GOOS == "linux" && (cfg.Carrier != "" && cfg.Carrier != "direct" || provision.SocketAvailable()) {
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				if _, err := provision.Call(ctx, "release", provision.Request{ID: id}); err != nil {
					return err
				}
			}
			return config.GlobalConfig.UpdateTunnelStatus(id, "inactive")
		}
		return errors.New("tunnel is not running")
	}
	if config.GlobalConfig != nil {
		if err := config.GlobalConfig.UpdateTunnelStatus(id, "inactive"); err != nil {
			return err
		}
	}
	delete(m.handlers, id)

	handler.Stop()
	if managed, ok := handler.(interface{ CleanupError() error }); ok {
		return managed.CleanupError()
	}
	return nil
}

// UpdateTunnel applies edits immediately to running tunnels and restores the
// previous configuration and listeners if the replacement cannot start.
func (m *CentralManager) UpdateTunnel(cfg *config.TunnelConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	previous, err := config.GlobalConfig.GetTunnel(cfg.ID)
	if err != nil {
		return err
	}
	cfg.Status = previous.Status
	if err := config.GlobalConfig.UpdateTunnel(cfg); err != nil {
		return err
	}
	cfg, err = config.GlobalConfig.GetTunnel(cfg.ID)
	if err != nil {
		return err
	}
	running, ok := m.handlers[cfg.ID]
	if !ok {
		return nil
	}
	running.Stop()
	delete(m.handlers, cfg.ID)
	updated, err := newHandler(cfg)
	if err == nil {
		err = updated.Start()
	}
	if err == nil {
		m.handlers[cfg.ID] = updated
		return nil
	}
	if updated != nil {
		updated.Stop()
	}
	if rollbackErr := config.GlobalConfig.UpdateTunnel(previous); rollbackErr != nil {
		return fmt.Errorf("restart failed: %v; config rollback failed: %w", err, rollbackErr)
	}
	restored, restoreErr := newHandler(previous)
	if restoreErr == nil {
		restoreErr = restored.Start()
	}
	if restoreErr != nil {
		if restored != nil {
			restored.Stop()
		}
		return fmt.Errorf("restart failed: %v; listener rollback failed: %w", err, restoreErr)
	}
	m.handlers[cfg.ID] = restored
	return fmt.Errorf("restart failed; previous tunnel restored: %w", err)
}

// GetActiveTunnelsCount reports how many tunnels are currently running.
func (m *CentralManager) GetActiveTunnelsCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.handlers)
}

// StopAll stops every running tunnel (graceful shutdown path).
func (m *CentralManager) StopAll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	handlers := m.handlers
	m.handlers = make(map[string]TunnelHandler)

	for _, handler := range handlers {
		handler.Stop()
	}
}

// StartConfiguredActiveTunnels auto-starts tunnels marked active in the
// persisted config. Tunnels still configured with removed protocols are
// logged loudly and left stopped.
func StartConfiguredActiveTunnels() {
	if config.GlobalConfig == nil {
		return
	}
	tunnels := config.GlobalConfig.GetTunnels()
	for _, t := range tunnels {
		if t.Status != "active" {
			continue
		}
		system.LogInfo("Auto-starting tunnel [%s]", t.Name)
		err := GlobalTunnelManager.StartTunnel(t)
		if err != nil {
			system.LogError("Failed to auto-start tunnel [%s]: %v", t.Name, err)
			_ = config.GlobalConfig.UpdateTunnelStatus(t.ID, "inactive")
		}
	}
}
