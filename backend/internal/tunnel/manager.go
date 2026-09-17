package tunnel

import (
	"errors"
	"fmt"
	"sync"

	"github.com/Meytiz/HESAR/backend/internal/config"
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
)

func newHandler(cfg *config.TunnelConfig) (TunnelHandler, error) {
	switch cfg.Protocol {
	case ProtocolTCP:
		return NewTCPHandler(cfg), nil
	case ProtocolKCP:
		return NewKCPHandler(cfg), nil
	case ProtocolQUIC:
		return NewQUICHandler(cfg), nil
	case "tls", "sni_spoof", "ip_spoof":
		return nil, fmt.Errorf("protocol %q has been REMOVED in HESAR vNext (use 'quic', 'tcp' or 'kcp')", cfg.Protocol)
	default:
		return nil, fmt.Errorf("unsupported protocol: %s", cfg.Protocol)
	}
}

// StartTunnel serializes start/restart against stop and shutdown.
func (m *CentralManager) StartTunnel(cfg *config.TunnelConfig) error {
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
		_ = config.GlobalConfig.UpdateTunnelStatus(cfg.ID, "active")
	}
	return nil
}

// StopTunnel stops a running tunnel.
func (m *CentralManager) StopTunnel(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	handler, exists := m.handlers[id]
	if !exists {
		return errors.New("tunnel is not running")
	}
	delete(m.handlers, id)

	handler.Stop()
	if config.GlobalConfig != nil {
		_ = config.GlobalConfig.UpdateTunnelStatus(id, "inactive")
	}
	return nil
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

	for id, handler := range handlers {
		handler.Stop()
		if config.GlobalConfig != nil {
			_ = config.GlobalConfig.UpdateTunnelStatus(id, "inactive")
		}
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
