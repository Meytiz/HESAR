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
// vNext hardening: StartTunnel now reserves the map slot BEFORE calling
// handler.Start(), eliminating the previous TOCTOU window where two
// concurrent StartTunnel calls for the same ID could both construct and
// start handlers (double-listen on the same ports, orphaned handler
// goroutines, corrupted status bookkeeping).
type CentralManager struct {
	mu       sync.Mutex
	handlers map[string]TunnelHandler
}

// GlobalTunnelManager is the process-wide tunnel registry.
var GlobalTunnelManager = &CentralManager{
	handlers: make(map[string]TunnelHandler),
}

// Protocol identifiers accepted by the vNext manager. "sni_spoof" and
// "ip_spoof" are intentionally gone — see the SNI-removal and IP-tunneling
// notes in the release documentation.
const (
	ProtocolTCP  = "tcp"
	ProtocolKCP  = "kcp"
	ProtocolQUIC = "quic"
	ProtocolTLS  = "tls"
)

func newHandler(cfg *config.TunnelConfig) (TunnelHandler, error) {
	switch cfg.Protocol {
	case ProtocolTCP:
		return NewTCPHandler(cfg), nil
	case ProtocolKCP:
		return NewKCPHandler(cfg), nil
	case ProtocolQUIC:
		return NewQUICHandler(cfg), nil
	case ProtocolTLS:
		return NewTLSFallbackHandler(cfg), nil
	case "sni_spoof", "ip_spoof":
		return nil, fmt.Errorf("protocol %q has been REMOVED in HESAR vNext (use 'quic' or 'tls')", cfg.Protocol)
	default:
		return nil, fmt.Errorf("unsupported protocol: %s", cfg.Protocol)
	}
}

// StartTunnel starts (or atomically restarts) the tunnel identified by
// cfg.ID. The map slot is reserved under the manager lock before Start()
// runs, so concurrent starts of the same tunnel are serialized.
func (m *CentralManager) StartTunnel(cfg *config.TunnelConfig) error {
	handler, err := newHandler(cfg)
	if err != nil {
		return err
	}

	m.mu.Lock()
	if existing, ok := m.handlers[cfg.ID]; ok {
		existing.Stop()
		delete(m.handlers, cfg.ID)
	}
	m.handlers[cfg.ID] = handler // reserve slot before Start()
	m.mu.Unlock()

	if err := handler.Start(); err != nil {
		m.mu.Lock()
		if m.handlers[cfg.ID] == handler {
			delete(m.handlers, cfg.ID)
		}
		m.mu.Unlock()
		return err
	}

	if config.GlobalConfig != nil {
		_ = config.GlobalConfig.UpdateTunnelStatus(cfg.ID, "active")
	}
	return nil
}

// StopTunnel stops a running tunnel.
func (m *CentralManager) StopTunnel(id string) error {
	m.mu.Lock()
	handler, exists := m.handlers[id]
	if !exists {
		m.mu.Unlock()
		return errors.New("tunnel is not running")
	}
	delete(m.handlers, id)
	m.mu.Unlock()

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
	handlers := m.handlers
	m.handlers = make(map[string]TunnelHandler)
	m.mu.Unlock()

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
