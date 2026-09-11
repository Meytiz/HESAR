package config

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func newTestManager(t *testing.T) *Manager {
	t.Helper()
	m, err := NewManager(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	return m
}

func validTunnel(id string) *TunnelConfig {
	return &TunnelConfig{
		ID:            id,
		Name:          "bridge",
		Mode:          "overseas",
		Protocol:      "quic",
		Status:        "active",
		RemotePort:    443,
		TargetPort:    8080,
		EncryptionKey: strings.Repeat("a", 32),
	}
}

// The panel's edit form posts only the editable fields: no status, and only
// the masked key. UpdateTunnel must treat both as "unchanged" — wiping the
// status silently disabled auto-start for a running tunnel after any edit, and
// a bogus status must be refused rather than persisted.
func TestUpdateTunnelPreservesOmittedStatusAndKey(t *testing.T) {
	m := newTestManager(t)

	created := validTunnel("t1")
	if err := m.AddTunnel(created); err != nil {
		t.Fatalf("AddTunnel: %v", err)
	}

	edit := &TunnelConfig{
		ID:         "t1",
		Name:       "bridge-renamed",
		Mode:       "overseas",
		Protocol:   "quic",
		RemotePort: 444,
		TargetPort: 8080,
	}
	if err := m.UpdateTunnel(edit); err != nil {
		t.Fatalf("UpdateTunnel: %v", err)
	}

	got, err := m.GetTunnel("t1")
	if err != nil {
		t.Fatalf("GetTunnel: %v", err)
	}
	if got.Name != "bridge-renamed" {
		t.Errorf("Name = %q, want the edited value", got.Name)
	}
	if got.RemotePort != 444 {
		t.Errorf("RemotePort = %d, want 444", got.RemotePort)
	}
	if got.Status != "active" {
		t.Errorf("Status = %q, want the stored %q to be kept", got.Status, "active")
	}
	if got.EncryptionKey != created.EncryptionKey {
		t.Error("EncryptionKey must be kept when the caller sends no key")
	}

	// A rejected update must not damage the stored tunnel.
	bad := &TunnelConfig{
		ID:         "t1",
		Name:       "bridge-broken",
		Mode:       "overseas",
		Protocol:   "quic",
		Status:     "running",
		RemotePort: 443,
		TargetPort: 8080,
	}
	if err := m.UpdateTunnel(bad); err == nil {
		t.Fatal("a status that is neither active nor inactive must be rejected")
	} else if !strings.Contains(err.Error(), "invalid status") {
		t.Fatalf("unexpected rejection reason: %v", err)
	}

	after, err := m.GetTunnel("t1")
	if err != nil {
		t.Fatalf("GetTunnel after rejected update: %v", err)
	}
	if after.Name != "bridge-renamed" || after.Status != "active" {
		t.Errorf("stored tunnel was modified by a rejected update: %+v", after)
	}
}

func TestRemovedProtocolsAreRejectedWithAGuide(t *testing.T) {
	m := newTestManager(t)

	legacy := validTunnel("t2")
	legacy.Protocol = "sni_spoof"
	err := m.AddTunnel(legacy)
	if err == nil {
		t.Fatal("the removed sni_spoof protocol must not be creatable")
	}
	if !strings.Contains(err.Error(), "REMOVED") {
		t.Errorf("error should explain the removal and the replacement, got: %v", err)
	}
}

// ErrTunnelNotFound is the sentinel the HTTP layer relies on to answer 404 for
// a missing tunnel instead of 404 for a rejected payload.
func TestMissingTunnelIDReturnsSentinel(t *testing.T) {
	m := newTestManager(t)

	if _, err := m.GetTunnel("missing"); !errors.Is(err, ErrTunnelNotFound) {
		t.Errorf("GetTunnel: got %v, want ErrTunnelNotFound", err)
	}
	if err := m.DeleteTunnel("missing"); !errors.Is(err, ErrTunnelNotFound) {
		t.Errorf("DeleteTunnel: got %v, want ErrTunnelNotFound", err)
	}
	if err := m.UpdateTunnel(validTunnel("missing")); !errors.Is(err, ErrTunnelNotFound) {
		t.Errorf("UpdateTunnel: got %v, want ErrTunnelNotFound", err)
	}
}

func TestAtomicSaveProducesReadableConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "config.json")

	m, err := NewManager(path)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if err := m.AddTunnel(validTunnel("t9")); err != nil {
		t.Fatalf("AddTunnel: %v", err)
	}

	reloaded, err := NewManager(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	got, err := reloaded.GetTunnel("t9")
	if err != nil {
		t.Fatalf("GetTunnel after reload: %v", err)
	}
	if got.Protocol != "quic" || got.Status != "active" {
		t.Errorf("persisted tunnel mismatch: %+v", got)
	}
}
