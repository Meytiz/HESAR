package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/Meytiz/HESAR/backend/internal/config"
	"github.com/Meytiz/HESAR/backend/internal/system"
	"github.com/Meytiz/HESAR/backend/internal/tunnel"
	"github.com/Meytiz/HESAR/backend/internal/tunnel/crypto"
	"github.com/Meytiz/HESAR/backend/internal/tunnel/tester"
	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin:     isOriginAllowed,
}

// isOriginAllowed enforces an exact-match Origin check to prevent
// Cross-Site WebSocket Hijacking. A request is accepted only if:
//   - it has no Origin header (non-browser / same-process clients), or
//   - the Origin's host exactly equals the request Host (scheme-agnostic
//     same-origin case), or
//   - the full Origin (scheme://host[:port]) exactly matches an entry
//     in the configured allowlist.
//
// Substring/Contains matching is intentionally NOT used: it allows
// attacker-controlled origins such as "https://evil.com/?host=panel.example.com"
// or "https://panel.example.com.evil.com" to pass a naive check.
func isOriginAllowed(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}

	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		system.LogWarn("WebSocket upgrade rejected: unparsable Origin %q", origin)
		return false
	}

	if strings.EqualFold(u.Host, r.Host) {
		return true
	}

	for _, allowed := range config.GlobalConfig.GetAllowedOrigins() {
		allowedURL, err := url.Parse(allowed)
		if err != nil {
			continue
		}
		if strings.EqualFold(u.Scheme, allowedURL.Scheme) && strings.EqualFold(u.Host, allowedURL.Host) {
			return true
		}
	}

	system.LogWarn("WebSocket upgrade rejected: Origin %q not allowed for Host %q", origin, r.Host)
	return false
}

// validateOriginEntry ensures each configured allowlist entry is an
// absolute URL of the form scheme://host[:port] with no path, query,
// or fragment — preventing ambiguous or overly-broad entries.
func validateOriginEntry(raw string) error {
	if raw == "" {
		return fmt.Errorf("origin entry cannot be empty")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid origin %q: %v", raw, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("invalid origin %q: scheme must be http or https", raw)
	}
	if u.Host == "" {
		return fmt.Errorf("invalid origin %q: missing host", raw)
	}
	if u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("invalid origin %q: must be scheme://host[:port] only", raw)
	}
	return nil
}

func generateSecureID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return "tunnel_" + hex.EncodeToString(b)
}

var validIDRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

func extractIDFromPath(path string) (string, error) {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) < 3 {
		return "", fmt.Errorf("invalid path")
	}
	id := parts[len(parts)-1]
	if id == "start" || id == "stop" {
		id = parts[len(parts)-2]
	}
	if !validIDRegex.MatchString(id) {
		return "", fmt.Errorf("invalid tunnel ID format")
	}
	return id, nil
}

func maskKey(key string) string {
	if len(key) <= 8 {
		return "****"
	}
	return key[:4] + "****" + key[len(key)-4:]
}

// maxJSONBodyBytes caps every request body accepted by the panel. The old
// code passed r.Body straight to json.NewDecoder with no limit — a client
// could stream an arbitrarily large body and pin memory/CPU on decode.
const maxJSONBodyBytes = 1 << 20 // 1 MiB is far beyond any legitimate panel request

// decodeJSONBody wraps http.MaxBytesReader around the request body before
// decoding. Returns false (after writing an error response) on any failure.
func decodeJSONBody(w http.ResponseWriter, r *http.Request, v interface{}) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxJSONBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return false
	}
	return true
}

func ConfigGetHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	cfg := config.GlobalConfig.GetConfig()
	cfg.AdminPassword = ""
	cfg.SecretKey = ""
	for _, t := range cfg.Tunnels {
		t.EncryptionKey = maskKey(t.EncryptionKey)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(cfg)
}

func ConfigUpdateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		AdminUsername  string   `json:"admin_username"`
		AdminPassword  string   `json:"admin_password"`
		LogPath        string   `json:"log_path"`
		LogMaxSizeMB   int      `json:"log_max_size_mb"`
		AllowedOrigins []string `json:"allowed_origins"`
	}
	if !decodeJSONBody(w, r, &req) {
		return
	}
	if err := config.GlobalConfig.UpdateSettings(req.AdminUsername, req.AdminPassword, req.LogPath, req.LogMaxSizeMB); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// Credential change ⇒ kill every live session: rotate the JWT signing
	// key so all previously issued tokens stop validating immediately.
	if req.AdminPassword != "" {
		if err := config.GlobalConfig.RotateSecretKey(); err != nil {
			jsonError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		system.LogWarn("GUI password changed — JWT signing key rotated; all sessions invalidated")
	}
	if req.AllowedOrigins != nil {
		for _, o := range req.AllowedOrigins {
			if err := validateOriginEntry(o); err != nil {
				jsonError(w, err.Error(), http.StatusBadRequest)
				return
			}
		}
		if err := config.GlobalConfig.SetAllowedOrigins(req.AllowedOrigins); err != nil {
			jsonError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		system.LogInfo("GUI Allowed WebSocket origins updated (%d entries)", len(req.AllowedOrigins))
	}
	if system.GlobalLogger != nil && req.LogPath != "" {
		_ = system.GlobalLogger.UpdateConfig(req.LogPath, req.LogMaxSizeMB)
	}
	system.LogInfo("GUI Settings updated successfully")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"message": "Settings updated successfully"})
}

func TunnelsListHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	tunnels := config.GlobalConfig.GetTunnels()
	for _, t := range tunnels {
		t.EncryptionKey = maskKey(t.EncryptionKey)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(tunnels)
}

func TunnelSaveHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var t config.TunnelConfig
	if !decodeJSONBody(w, r, &t) {
		return
	}
	if t.ID == "" {
		t.ID = generateSecureID()
		if err := config.GlobalConfig.AddTunnel(&t); err != nil {
			jsonError(w, err.Error(), http.StatusBadRequest)
			return
		}
	} else {
		if err := config.GlobalConfig.UpdateTunnel(&t); err != nil {
			jsonError(w, err.Error(), http.StatusNotFound)
			return
		}
	}
	system.LogInfo("Tunnel [%s] saved successfully", t.Name)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(t)
}

func TunnelDeleteHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id, err := extractIDFromPath(r.URL.Path)
	if err != nil {
		jsonError(w, "invalid tunnel ID", http.StatusBadRequest)
		return
	}
	_ = tunnel.GlobalTunnelManager.StopTunnel(id)
	if err := config.GlobalConfig.DeleteTunnel(id); err != nil {
		jsonError(w, err.Error(), http.StatusNotFound)
		return
	}
	system.LogInfo("Tunnel ID [%s] deleted", id)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"message": "Tunnel deleted"})
}

func TunnelStartHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id, err := extractIDFromPath(r.URL.Path)
	if err != nil {
		jsonError(w, "invalid path", http.StatusBadRequest)
		return
	}
	t, err := config.GlobalConfig.GetTunnel(id)
	if err != nil {
		jsonError(w, err.Error(), http.StatusNotFound)
		return
	}
	if err := tunnel.GlobalTunnelManager.StartTunnel(t); err != nil {
		jsonError(w, fmt.Sprintf("Failed to start tunnel: %v", err), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"message": "Tunnel started"})
}

func TunnelStopHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id, err := extractIDFromPath(r.URL.Path)
	if err != nil {
		jsonError(w, "invalid path", http.StatusBadRequest)
		return
	}
	if err := tunnel.GlobalTunnelManager.StopTunnel(id); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"message": "Tunnel stopped"})
}

func StatsGetHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	metrics := system.GetSystemMetrics()
	tunnels := config.GlobalConfig.GetTunnels()
	total := len(tunnels)
	active := tunnel.GlobalTunnelManager.GetActiveTunnelsCount()
	panelUptime := int64(time.Since(config.StartTime).Seconds())
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"total_tunnels":    total,
		"active_tunnels":   active,
		"inactive_tunnels": total - active,
		"cpu_usage":        metrics.CPUUsage,
		"memory_total":     metrics.MemoryTotal,
		"memory_used":      metrics.MemoryUsed,
		"memory_usage":     metrics.MemoryUsage,
		"load_avg_1":       metrics.LoadAvg1,
		"bbr_active":       metrics.BBRActive,
		"panel_uptime":     panelUptime,
	})
}

func OptimizeExecHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var warnings []string

	if err := system.EnableBBR(); err != nil {
		warnings = append(warnings, fmt.Sprintf("BBR: %v", err))
	}

	if err := system.OptimizeNetwork(); err != nil {
		warnings = append(warnings, fmt.Sprintf("Network: %v", err))
	}

	bbrActive := system.CheckBBR()

	if len(warnings) > 0 && !bbrActive {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success":    false,
			"bbr_active": bbrActive,
			"message":    "Optimization requires root. Run: sudo ./hesar.sh --optimize",
			"warnings":   warnings,
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"success":    true,
		"bbr_active": bbrActive,
		"message":    "Server Optimization & BBR applied successfully!",
	})
}

// ──────────────────────────────────────────────────
// vNext tester endpoints.
//
// The legacy /api/tester/sni and /api/tester/ip endpoints are GONE together
// with the SNI-Spoof / IP-Spoof features they advertised. The replacements
// run real protocol probes (see internal/tunnel/tester) and share one SSRF
// guard that refuses private/loopback/metadata targets.
// ──────────────────────────────────────────────────

func TesterTCPHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		TargetIP string `json:"target_ip"`
		Port     int    `json:"port"`
	}
	if !decodeJSONBody(w, r, &req) {
		return
	}
	res := tester.RunTCPTest(req.TargetIP, req.Port)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(res)
}

func TesterTLSHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		TargetIP   string `json:"target_ip"`
		Port       int    `json:"port"`
		ServerName string `json:"server_name"`
	}
	if !decodeJSONBody(w, r, &req) {
		return
	}
	res := tester.RunTLSTest(req.TargetIP, req.Port, req.ServerName)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(res)
}

func TesterQUICHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		TargetIP string `json:"target_ip"`
		Port     int    `json:"port"`
	}
	if !decodeJSONBody(w, r, &req) {
		return
	}
	res := tester.RunQUICTest(req.TargetIP, req.Port)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(res)
}

func KeyGenHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	noiseKeys, err := crypto.GenerateX25519KeyPair()
	if err != nil {
		jsonError(w, "failed to generate key pair", http.StatusInternalServerError)
		return
	}
	masterHex, err := crypto.GenerateRandomHexKey(32)
	if err != nil {
		jsonError(w, "failed to generate random key", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"noise_private_key": fmt.Sprintf("%x", noiseKeys.PrivateKey),
		"noise_public_key":  fmt.Sprintf("%x", noiseKeys.PublicKey),
		"encryption_key":    masterHex,
	})
}

func LogsWebSocketHandler(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		system.LogError("WebSocket upgrade failed: %v", err)
		return
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		return nil
	})

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			if _, _, readErr := conn.ReadMessage(); readErr != nil {
				break
			}
		}
	}()

	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	if system.GlobalLogger == nil {
		_ = conn.WriteJSON(system.LogMessage{
			Timestamp: time.Now().Format("2006-01-02 15:04:05"),
			Level:     "WARN",
			Message:   "Logger is not fully initialized.",
		})
		return
	}

	logCh := system.GlobalLogger.Subscribe()
	defer system.GlobalLogger.Unsubscribe(logCh)

	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		case msg, ok := <-logCh:
			if !ok {
				return
			}
			if err := conn.WriteJSON(msg); err != nil {
				return
			}
		}
	}
}
