package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Meytiz/HESAR/backend/internal/config"
	"github.com/Meytiz/HESAR/backend/internal/system"
	"github.com/golang-jwt/jwt/v5"
)

func testConfig(t *testing.T) *config.Manager {
	t.Helper()
	m, err := config.NewManager(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	previous := config.GlobalConfig
	config.GlobalConfig = m
	t.Cleanup(func() { config.GlobalConfig = previous })
	return m
}
func TestJWTRequiresExpiryAndHS256(t *testing.T) {
	m := testConfig(t)
	for _, tc := range []struct {
		method  jwt.SigningMethod
		expires bool
		want    int
	}{{jwt.SigningMethodHS256, false, 401}, {jwt.SigningMethodHS384, true, 401}, {jwt.SigningMethodHS256, true, 204}} {
		claims := jwt.MapClaims{"iss": jwtIssuer, "aud": jwtAudience}
		if tc.expires {
			claims["exp"] = time.Now().Add(time.Hour).Unix()
		}
		tok, err := jwt.NewWithClaims(tc.method, claims).SignedString([]byte(m.GetSecretKey()))
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest("GET", "/api/config", nil)
		r.Header.Set("Authorization", "Bearer "+tok)
		w := httptest.NewRecorder()
		AuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })).ServeHTTP(w, r)
		if w.Code != tc.want {
			t.Fatalf("status %d, want %d", w.Code, tc.want)
		}
	}
}
func TestTicketInvalidatedByCredentialChange(t *testing.T) {
	m := testConfig(t)
	store := &wsTicketStore{tickets: make(map[string]wsTicketEntry)}
	ticket, err := store.issue("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if err := m.UpdateSettings("another-admin", "", "", 0); err != nil {
		t.Fatal(err)
	}
	if store.consume(ticket, "127.0.0.1") {
		t.Fatal("old session ticket remained valid")
	}
}
func TestInvalidOriginsDoNotPartiallyChangeSettings(t *testing.T) {
	m := testConfig(t)
	before := m.GetConfig()
	r := httptest.NewRequest("POST", "/api/config", strings.NewReader(`{"admin_username":"changed","allowed_origins":["http://example.com/path"]}`))
	w := httptest.NewRecorder()
	ConfigUpdateHandler(w, r)
	if w.Code != 400 {
		t.Fatal(w.Code)
	}
	if m.GetConfig().AdminUsername != before.AdminUsername {
		t.Fatal("invalid origins partially committed")
	}
}
func TestUnwritableLogPathDoesNotChangeCredentials(t *testing.T) {
	m := testConfig(t)
	before := m.GetConfig()
	previous := system.GlobalLogger
	if err := system.InitLogger(filepath.Join(t.TempDir(), "hesar.log"), 10); err != nil {
		t.Fatal(err)
	}
	logger := system.GlobalLogger
	t.Cleanup(func() { logger.Close(); system.GlobalLogger = previous })
	blocker := filepath.Join(t.TempDir(), "file-not-directory")
	if err := os.WriteFile(blocker, []byte("block"), 0600); err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(map[string]any{"admin_username": "changed", "log_path": filepath.Join(blocker, "hesar.log")})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	ConfigUpdateHandler(w, httptest.NewRequest("POST", "/api/config", bytes.NewReader(body)))
	if w.Code != 400 {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	after := m.GetConfig()
	if after.AdminUsername != before.AdminUsername || after.SecretKey != before.SecretKey || after.LogPath != before.LogPath {
		t.Fatal("invalid log path partially changed settings")
	}
}
func TestJSONRejectsTrailingValue(t *testing.T) {
	var value map[string]interface{}
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/", strings.NewReader(`{} {}`))
	if decodeJSONBody(w, r, &value) || w.Code != 400 {
		t.Fatal("trailing JSON accepted")
	}
}
func TestExpiredLoginBucketsAreSwept(t *testing.T) {
	rl := &rateLimiter{attempts: map[string][]time.Time{"old": {time.Now().Add(-time.Hour)}}, max: 5, window: time.Minute}
	if !rl.isAllowed("new") {
		t.Fatal("unexpected rejection")
	}
	if _, ok := rl.attempts["old"]; ok {
		t.Fatal("unrelated expired bucket leaked")
	}
}
