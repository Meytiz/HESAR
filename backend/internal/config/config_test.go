package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func validTunnel() *TunnelConfig {
	return &TunnelConfig{ID: "test", Name: "test", Mode: "iran", Protocol: "tcp", LocalPorts: "8080", RemoteIP: "127.0.0.1", RemotePort: 443, EncryptionKey: strings.Repeat("a", 64)}
}
func TestPortValidation(t *testing.T) {
	for _, bad := range []string{"", "1-65535", "0", "65536", "9-1", "3-x", "1-64,65"} {
		if _, err := ParsePorts(bad); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
	ports, err := ParsePorts("80,80, 443,8000-8002")
	if err != nil || len(ports) != 5 {
		t.Fatal(ports, err)
	}
}
func TestNetworkValidation(t *testing.T) {
	for _, mutate := range []func(*TunnelConfig){
		func(c *TunnelConfig) { c.QUICEnableUDP = true }, func(c *TunnelConfig) { c.RemoteIP = "bad host" },
		func(c *TunnelConfig) { c.TLSFragmentSize = 16 }, func(c *TunnelConfig) { c.DialTimeoutSeconds = -1 },
		func(c *TunnelConfig) { c.ProxyURL = "http://127.0.0.1:8080" }, func(c *TunnelConfig) { c.LocalPorts = "1-65535" },
		func(c *TunnelConfig) { c.Protocol = "wss"; c.ServerName = "" },
	} {
		c := validTunnel()
		mutate(c)
		if err := ValidateTunnel(c); err == nil {
			t.Fatal("invalid config accepted")
		}
	}
}

func TestUnderlayRejectsUnsafeCombinations(t *testing.T) {
	for _, change := range []func(*TunnelConfig){
		func(c *TunnelConfig) { c.UnderlayInterface = "../../eth0" },
		func(c *TunnelConfig) { c.ProxyURL = "socks5://127.0.0.1:10808" },
		func(c *TunnelConfig) { c.RemoteIP = "8.8.8.8" },
		func(c *TunnelConfig) { c.Protocol = "auto"; c.ServerName = "example.com" },
		func(c *TunnelConfig) { c.Mode = "overseas"; c.ListenAddress = "0.0.0.0"; c.TargetPort = 8080 },
		func(c *TunnelConfig) { c.UnderlayInterface = "" },
	} {
		c := validTunnel()
		c.RemoteIP, c.NetworkProfile, c.UnderlayInterface = "10.77.0.2", "l3-gre", "hsl3-link"
		change(c)
		if ValidateTunnel(c) == nil {
			t.Fatal("unsafe L3 combination accepted")
		}
	}
}
func TestFailedSaveRollsBackMemory(t *testing.T) {
	dir := t.TempDir()
	m, err := NewManager(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	before := m.GetConfig()
	block := filepath.Join(dir, "file")
	if err := os.WriteFile(block, []byte("not a directory"), 0600); err != nil {
		t.Fatal(err)
	}
	m.configPath = filepath.Join(block, "config.json")
	if err := m.UpdateSettings("changed", "changed-password", "", 0); err == nil {
		t.Fatal("expected persistence failure")
	}
	after := m.GetConfig()
	if after.AdminUsername != before.AdminUsername || after.SecretKey != before.SecretKey {
		t.Fatal("failed settings changed live credentials")
	}
	if err := m.AddTunnel(validTunnel()); err == nil {
		t.Fatal("expected tunnel persistence failure")
	}
	if len(m.GetTunnels()) != 0 {
		t.Fatal("unsaved tunnel leaked into memory")
	}
}
func TestCallerCannotMutateStoredTunnel(t *testing.T) {
	m, err := NewManager(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	c := validTunnel()
	if err := m.AddTunnel(c); err != nil {
		t.Fatal(err)
	}
	c.Name = "changed"
	stored, _ := m.GetTunnel(c.ID)
	if stored.Name == "changed" {
		t.Fatal("stored caller pointer")
	}
}
func TestCredentialChangeRotatesOnlyWhenNeeded(t *testing.T) {
	m, err := NewManager(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	old := m.GetSecretKey()
	if err := m.UpdateSettings("", "", "", 20); err != nil {
		t.Fatal(err)
	}
	if old != m.GetSecretKey() {
		t.Fatal("noncredential edit rotated sessions")
	}
	if err := m.UpdateSettings("new-user", "", "", 0); err != nil {
		t.Fatal(err)
	}
	if old == m.GetSecretKey() {
		t.Fatal("username change left sessions valid")
	}
}
