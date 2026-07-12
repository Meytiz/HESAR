package tunnel

import (
	"errors"
	"fmt"
	"sync"

	"github.com/Meytiz/HESAR/backend/internal/config"
	"github.com/Meytiz/HESAR/backend/internal/system"
)

type TunnelHandler interface {
	Start() error
	Stop()
}

type CentralManager struct {
	mu       sync.Mutex
	handlers map[string]TunnelHandler
}

var GlobalTunnelManager = &CentralManager{
	handlers: make(map[string]TunnelHandler),
}

func (m *CentralManager) StartTunnel(cfg *config.TunnelConfig) error {
	m.mu.Lock()
	if existing, ok := m.handlers[cfg.ID]; ok {
		existing.Stop()
		delete(m.handlers, cfg.ID)
	}
	m.mu.Unlock()

	var handler TunnelHandler
	switch cfg.Protocol {
	case "tcp":
		handler = NewTCPHandler(cfg)
	case "kcp":
		handler = NewKCPHandler(cfg)
	case "sni_spoof":
		handler = NewSNISpoofHandler(cfg)
	case "ip_spoof":
		handler = NewIPSpoofHandler(cfg)
	default:
		return fmt.Errorf("unsupported protocol: %s", cfg.Protocol)
	}

	if err := handler.Start(); err != nil {
		return err
	}

	m.mu.Lock()
	m.handlers[cfg.ID] = handler
	m.mu.Unlock()

	if config.GlobalConfig != nil {
		_ = config.GlobalConfig.UpdateTunnelStatus(cfg.ID, "active")
	}
	return nil
}

func (m *CentralManager) StopTunnel(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	handler, exists := m.handlers[id]
	if !exists {
		return errors.New("tunnel is not running")
	}
	handler.Stop()
	delete(m.handlers, id)
	if config.GlobalConfig != nil {
		_ = config.GlobalConfig.UpdateTunnelStatus(id, "inactive")
	}
	return nil
}

func (m *CentralManager) GetActiveTunnelsCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.handlers)
}

func (m *CentralManager) StopAll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, handler := range m.handlers {
		handler.Stop()
		if config.GlobalConfig != nil {
			_ = config.GlobalConfig.UpdateTunnelStatus(id, "inactive")
		}
	}
	m.handlers = make(map[string]TunnelHandler)
}

func StartConfiguredActiveTunnels() {
	if config.GlobalConfig == nil {
		return
	}
	tunnels := config.GlobalConfig.GetTunnels()
	for _, t := range tunnels {
		if t.Status == "active" {
			system.LogInfo("Auto-starting tunnel [%s]", t.Name)
			err := GlobalTunnelManager.StartTunnel(t)
			if err != nil {
				system.LogError("Failed to auto-start tunnel [%s]: %v", t.Name, err)
				_ = config.GlobalConfig.UpdateTunnelStatus(t.ID, "inactive")
			}
		}
	}
}