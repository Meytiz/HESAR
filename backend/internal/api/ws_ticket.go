package api

import (
	"crypto/rand"
	"encoding/hex"
	"net"
	"net/http"
	"sync"
	"time"
)

// ──────────────────────────────────────────────────
// WebSocket short-lived ticket store
//
// The JWT (long-lived, high-value) must never appear in a URL: it leaks
// into web server access logs, intermediate proxy logs, browser history,
// and the Referer header. Instead, an authenticated REST call (JWT via
// Authorization header, as usual) issues a random, single-use, short-lived
// ticket. The WebSocket upgrade request then carries only this ticket as
// a query parameter — if it ever leaks, it is already expired/consumed
// within seconds and grants no lasting access.
// ──────────────────────────────────────────────────

const wsTicketTTL = 30 * time.Second

type wsTicketEntry struct {
	expiresAt time.Time
	remoteIP  string
}

type wsTicketStore struct {
	mu      sync.Mutex
	tickets map[string]wsTicketEntry
}

var wsTickets = &wsTicketStore{tickets: make(map[string]wsTicketEntry)}

// issue creates a new random ticket bound to the caller's remote IP
// (best-effort — behind a reverse proxy this is the proxy's IP, which is
// still consistent between the ticket-issuing call and the immediately
// following WebSocket upgrade from the same browser).
func (s *wsTicketStore) issue(remoteIP string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupLocked()

	b := make([]byte, 32)
	_, _ = rand.Read(b)
	ticket := hex.EncodeToString(b)

	s.tickets[ticket] = wsTicketEntry{
		expiresAt: time.Now().Add(wsTicketTTL),
		remoteIP:  remoteIP,
	}
	return ticket
}

// consume validates and immediately invalidates a ticket (single-use).
// It is deleted regardless of outcome to prevent replay/probing.
func (s *wsTicketStore) consume(ticket, remoteIP string) bool {
	if ticket == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, ok := s.tickets[ticket]
	delete(s.tickets, ticket)
	if !ok {
		return false
	}
	if time.Now().After(entry.expiresAt) {
		return false
	}
	if entry.remoteIP != "" && entry.remoteIP != remoteIP {
		return false
	}
	return true
}

// cleanupLocked drops expired tickets. Must be called with s.mu held.
func (s *wsTicketStore) cleanupLocked() {
	now := time.Now()
	for k, v := range s.tickets {
		if now.After(v.expiresAt) {
			delete(s.tickets, k)
		}
	}
}

// clientIP extracts the connection's remote IP without the port,
// falling back to the raw RemoteAddr if parsing fails.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// WSTicketHandler issues a short-lived, single-use ticket for the
// authenticated caller. Must be mounted behind AuthMiddleware.
func WSTicketHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ticket := wsTickets.issue(clientIP(r))
	writeJSON(w, map[string]interface{}{
		"ticket":     ticket,
		"expires_in": int(wsTicketTTL.Seconds()),
	})
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	_ = jsonEncode(w, v)
}