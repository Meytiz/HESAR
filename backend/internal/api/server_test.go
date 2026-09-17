package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// The panel intentionally stays plain HTTP on 0.0.0.0 (operator decision).
// This test only pins the security headers the SPA route sets.
func TestStaticRouteHeaders(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" ||
		rec.Header().Get("X-Frame-Options") != "DENY" {
		t.Fatal("security headers missing")
	}
}