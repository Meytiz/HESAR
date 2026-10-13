package tunnel

import (
	"net"
	"path/filepath"
	"strconv"
	"sync"
	"testing"

	"github.com/Meytiz/HESAR/backend/internal/config"
)

type lifecycleHandler struct {
	mu    sync.Mutex
	stops int
}

func (h *lifecycleHandler) Start() error { return nil }
func (h *lifecycleHandler) Stop()        { h.mu.Lock(); h.stops++; h.mu.Unlock() }

func TestShutdownPreservesAutostartIntent(t *testing.T) {
	m, err := config.NewManager(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	previous := config.GlobalConfig
	config.GlobalConfig = m
	defer func() { config.GlobalConfig = previous }()
	bridge, _ := testPair(t, "tcp", testPort(t))
	bridge.Status = "active"
	if err := m.AddTunnel(bridge); err != nil {
		t.Fatal(err)
	}
	h := &lifecycleHandler{}
	central := &CentralManager{handlers: map[string]TunnelHandler{bridge.ID: h}}
	central.StopAll()
	saved, _ := m.GetTunnel(bridge.ID)
	if saved.Status != "active" || h.stops != 1 {
		t.Fatal("shutdown erased autostart intent")
	}
}
func TestActiveEditFailureRestoresPreviousListener(t *testing.T) {
	m, err := config.NewManager(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	previous := config.GlobalConfig
	config.GlobalConfig = m
	defer func() { config.GlobalConfig = previous }()
	bridge, _ := testPair(t, "tcp", testPort(t))
	if err := m.AddTunnel(bridge); err != nil {
		t.Fatal(err)
	}
	central := &CentralManager{handlers: make(map[string]TunnelHandler)}
	defer central.StopAll()
	if err := central.StartTunnel(bridge); err != nil {
		t.Fatal(err)
	}
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	edited := *bridge
	edited.LocalPorts = strconv.Itoa(busy.Addr().(*net.TCPAddr).Port)
	if err := central.UpdateTunnel(&edited); err == nil {
		t.Fatal("accepted occupied port")
	}
	saved, _ := m.GetTunnel(bridge.ID)
	if saved.LocalPorts != bridge.LocalPorts || saved.Status != "active" {
		t.Fatal("config rollback failed")
	}
	probe, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", bridge.LocalPorts))
	if err == nil {
		probe.Close()
		t.Fatal("original listener was not restored")
	}
	if central.GetActiveTunnelsCount() != 1 {
		t.Fatal("runtime rollback failed")
	}
}
