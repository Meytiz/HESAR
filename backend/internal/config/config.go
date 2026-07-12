package config

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ──────────────────────────────────────────────────
// Data Structures
// ──────────────────────────────────────────────────

type TunnelConfig struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Mode          string `json:"mode"`          // "iran" or "overseas"
	Protocol      string `json:"protocol"`      // "kcp", "tcp", "ip_spoof", "sni_spoof"
	Status        string `json:"status"`        // "active" or "inactive"
	LocalPorts    string `json:"local_ports"`   // e.g. "80", "80,880", "80-100"
	RemoteIP      string `json:"remote_ip"`
	RemotePort    int    `json:"remote_port"`
	EncryptionKey string `json:"encryption_key"`
	TargetPort    int    `json:"target_port"`

	KCPMode  string `json:"kcp_mode"`
	SpoofSNI string `json:"spoof_sni"`
	FakeIP   string `json:"fake_ip"`

	BytesIn  int64 `json:"bytes_in"`
	BytesOut int64 `json:"bytes_out"`
	Uptime   int64 `json:"uptime"`
}

type AppConfig struct {
	AdminUsername string          `json:"admin_username"`
	AdminPassword string          `json:"admin_password"`
	ListenPort    int             `json:"listen_port"`
	LogPath       string          `json:"log_path"`
	LogMaxSizeMB  int             `json:"log_max_size_mb"`
	SecretKey     string          `json:"secret_key"`
	Tunnels       []*TunnelConfig `json:"tunnels"`
}

// SafeConfig — نسخه‌ای بدون اطلاعات حساس برای API
type SafeConfig struct {
	AdminUsername string `json:"admin_username"`
	ListenPort    int    `json:"listen_port"`
	LogPath       string `json:"log_path"`
	LogMaxSizeMB  int    `json:"log_max_size_mb"`
	TunnelCount   int    `json:"tunnel_count"`
}

type Manager struct {
	mu         sync.RWMutex
	configPath string
	config     *AppConfig
}

var (
	GlobalConfig *Manager
	StartTime    = time.Now()
)

// ──────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────

func generateRandomHex(length int) string {
	b := make([]byte, length)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func validateTunnel(t *TunnelConfig) error {
	if t.ID == "" {
		return errors.New("tunnel ID is required")
	}
	if t.Name == "" {
		return errors.New("tunnel name is required")
	}
	switch t.Mode {
	case "iran", "overseas":
	default:
		return fmt.Errorf("invalid mode %q: must be 'iran' or 'overseas'", t.Mode)
	}
	switch t.Protocol {
	case "kcp", "tcp", "ip_spoof", "sni_spoof":
	default:
		return fmt.Errorf("invalid protocol %q", t.Protocol)
	}
	if t.RemotePort < 1 || t.RemotePort > 65535 {
		return fmt.Errorf("remote_port must be 1-65535, got %d", t.RemotePort)
	}

	if t.Mode == "iran" {
		if t.RemoteIP == "" {
			return errors.New("remote_ip is required for iran mode")
		}
	}

	if t.Mode == "overseas" {
		if t.TargetPort < 1 || t.TargetPort > 65535 {
			return fmt.Errorf("target_port must be 1-65535 for overseas mode, got %d", t.TargetPort)
		}
	}

	if t.Protocol == "sni_spoof" && t.SpoofSNI == "" {
		return errors.New("spoof_sni is required for sni_spoof protocol")
	}
	if t.Protocol == "ip_spoof" && t.FakeIP == "" {
		return errors.New("fake_ip is required for ip_spoof protocol")
	}
	if t.Protocol == "kcp" {
		switch t.KCPMode {
		case "", "normal", "fast", "fast2", "fast3":
		default:
			return fmt.Errorf("invalid kcp_mode %q: must be normal, fast, fast2, or fast3", t.KCPMode)
		}
	}
	return nil
}

// ──────────────────────────────────────────────────
// Init
// ──────────────────────────────────────────────────

func NewManager(path string) (*Manager, error) {
	m := &Manager{configPath: path}
	err := m.Load()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			m.config = &AppConfig{
				AdminUsername: "admin",
				AdminPassword: generateRandomHex(16), // ✅ رمز تصادفی
				ListenPort:    8443,
				LogPath:       "hesar.log",
				LogMaxSizeMB:  10,
				SecretKey:     generateRandomHex(32), // ✅ کلید JWT تصادفی
				Tunnels:       []*TunnelConfig{},
			}
			if err := m.saveLocked(); err != nil {
				return nil, err
			}
			fmt.Println("⚠️  HESAR: First-run config generated.")
			fmt.Printf("   Admin Password: %s\n", m.config.AdminPassword)
			fmt.Println("   Please change it via the Web Panel immediately!")
		} else {
			return nil, err
		}
	}
	return m, nil
}

func InitGlobalConfig(path string) error {
	m, err := NewManager(path)
	if err != nil {
		return err
	}
	GlobalConfig = m
	return nil
}

// ──────────────────────────────────────────────────
// Load / Save (atomic)
// ──────────────────────────────────────────────────

func (m *Manager) Load() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	dir := filepath.Dir(m.configPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	data, err := os.ReadFile(m.configPath)
	if err != nil {
		return err
	}

	var cfg AppConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return err
	}

	if cfg.Tunnels == nil {
		cfg.Tunnels = []*TunnelConfig{}
	}
	m.config = &cfg
	return nil
}

// saveLocked — بدون قفل، فقط داخل متدی که از قبل lock دارد
func (m *Manager) saveLocked() error {
	dir := filepath.Dir(m.configPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	data, err := json.MarshalIndent(m.config, "", "  ")
	if err != nil {
		return err
	}

	// ✅ اتمیک: ابتدا فایل موقت، سپس rename
	tmpPath := m.configPath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmpPath, m.configPath)
}

func (m *Manager) Save() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.saveLocked()
}

// ──────────────────────────────────────────────────
// Getters
// ──────────────────────────────────────────────────

func (m *Manager) GetConfig() AppConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return AppConfig{
		AdminUsername: m.config.AdminUsername,
		AdminPassword: m.config.AdminPassword,
		ListenPort:    m.config.ListenPort,
		LogPath:       m.config.LogPath,
		LogMaxSizeMB:  m.config.LogMaxSizeMB,
		SecretKey:     m.config.SecretKey,
		Tunnels:       m.cloneTunnels(),
	}
}

func (m *Manager) GetSafeConfig() SafeConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return SafeConfig{
		AdminUsername: m.config.AdminUsername,
		ListenPort:    m.config.ListenPort,
		LogPath:       m.config.LogPath,
		LogMaxSizeMB:  m.config.LogMaxSizeMB,
		TunnelCount:   len(m.config.Tunnels),
	}
}

// cloneTunnels — باید با قفل صدا زده شود
func (m *Manager) cloneTunnels() []*TunnelConfig {
	list := make([]*TunnelConfig, len(m.config.Tunnels))
	for i, t := range m.config.Tunnels {
		tCopy := *t
		list[i] = &tCopy
	}
	return list
}

func (m *Manager) GetTunnels() []*TunnelConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cloneTunnels()
}

func (m *Manager) GetTunnel(id string) (*TunnelConfig, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, t := range m.config.Tunnels {
		if t.ID == id {
			tCopy := *t
			return &tCopy, nil
		}
	}
	return nil, errors.New("tunnel not found")
}

// ──────────────────────────────────────────────────
// Setters (with auto-save)
// ──────────────────────────────────────────────────

func (m *Manager) UpdateSettings(username, password string, logPath string, logMaxSizeMB int) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if username != "" {
		m.config.AdminUsername = username
	}
	if password != "" {
		m.config.AdminPassword = password
	}
	if logPath != "" {
		m.config.LogPath = logPath
	}
	if logMaxSizeMB > 0 {
		m.config.LogMaxSizeMB = logMaxSizeMB
	}

	return m.saveLocked() // ✅ ذخیره روی دیسک
}

func (m *Manager) AddTunnel(t *TunnelConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if err := validateTunnel(t); err != nil {
		return err // ✅ اعتبارسنجی
	}

	for _, existing := range m.config.Tunnels {
		if existing.ID == t.ID {
			return errors.New("tunnel with this ID already exists")
		}
	}

	if t.Status == "" {
		t.Status = "inactive"
	}
	m.config.Tunnels = append(m.config.Tunnels, t)
	return m.saveLocked() // ✅
}

func (m *Manager) UpdateTunnel(t *TunnelConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if err := validateTunnel(t); err != nil {
		return err // ✅ اعتبارسنجی
	}

	for i, existing := range m.config.Tunnels {
		if existing.ID == t.ID {
			t.BytesIn = existing.BytesIn
			t.BytesOut = existing.BytesOut
			t.Uptime = existing.Uptime
			m.config.Tunnels[i] = t
			return m.saveLocked() // ✅
		}
	}
	return errors.New("tunnel not found")
}

func (m *Manager) UpdateTunnelStatus(id string, status string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, t := range m.config.Tunnels {
		if t.ID == id {
			t.Status = status
			if status == "active" {
				t.Uptime = time.Now().Unix()
			} else {
				t.Uptime = 0
			}
			return m.saveLocked() // ✅
		}
	}
	return errors.New("tunnel not found")
}

func (m *Manager) UpdateTunnelStats(id string, bytesIn, bytesOut int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, t := range m.config.Tunnels {
		if t.ID == id {
			t.BytesIn += bytesIn  // ✅
			t.BytesOut += bytesOut // ✅ قبلاً نادیده گرفته شده بود
			return nil             // آمار runtime نیازی به save ندارد
		}
	}
	return errors.New("tunnel not found") // ✅
}

func (m *Manager) DeleteTunnel(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for i, existing := range m.config.Tunnels {
		if existing.ID == id {
			m.config.Tunnels = append(m.config.Tunnels[:i], m.config.Tunnels[i+1:]...)
			return m.saveLocked() // ✅
		}
	}
	return errors.New("tunnel not found")
}