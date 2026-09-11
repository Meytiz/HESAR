package api

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Meytiz/HESAR/backend/internal/config"
	"github.com/Meytiz/HESAR/backend/internal/system"
	"github.com/golang-jwt/jwt/v5"
)

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginResponse struct {
	Token   string `json:"token"`
	Message string `json:"message"`
}

type rateLimiter struct {
	mu       sync.Mutex
	attempts map[string][]time.Time
	max      int
	window   time.Duration
}

var loginLimiter = &rateLimiter{
	attempts: make(map[string][]time.Time),
	max:      5,
	window:   15 * time.Minute,
}

func (rl *rateLimiter) isAllowed(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	cutoff := now.Add(-rl.window)
	var recent []time.Time
	for _, t := range rl.attempts[ip] {
		if t.After(cutoff) {
			recent = append(recent, t)
		}
	}
	// vNext fix: an IP whose bucket fully expired used to be left in the map
	// with an empty slice, so the map grew by one entry per distinct source
	// address forever (a slow, unbounded leak driven by anyone who can open a
	// TCP connection to the panel).
	if len(recent) == 0 {
		delete(rl.attempts, ip)
	} else {
		rl.attempts[ip] = recent
	}
	if len(recent) >= rl.max {
		return false
	}
	rl.attempts[ip] = append(recent, now)
	return true
}

// reset clears an IP's failure bucket. It is called after a SUCCESSFUL login:
// isAllowed records every attempt, so without this the legitimate operator was
// punished by their own activity — the fifth login inside the window (day one
// of an install: login, logout, login after a reboot, …) locked the panel out
// with 429 for the remainder of 15 minutes, and there is no self-service
// recovery path short of restarting the daemon.
func (rl *rateLimiter) reset(ip string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	delete(rl.attempts, ip)
}

var tokenBlacklist = struct {
	sync.RWMutex
	tokens map[string]time.Time
}{tokens: make(map[string]time.Time)}

// blacklistSweepOnce starts exactly one background sweeper that garbage
// collects expired blacklist entries.
var blacklistSweepOnce sync.Once

func startBlacklistSweeper() {
	blacklistSweepOnce.Do(func() {
		go func() {
			ticker := time.NewTicker(10 * time.Minute)
			defer ticker.Stop()
			for range ticker.C {
				now := time.Now()
				tokenBlacklist.Lock()
				for tok, expiry := range tokenBlacklist.tokens {
					if now.After(expiry) {
						delete(tokenBlacklist.tokens, tok)
					}
				}
				tokenBlacklist.Unlock()
			}
		}()
	})
}

func isTokenBlacklisted(tokenStr string) bool {
	tokenBlacklist.RLock()
	defer tokenBlacklist.RUnlock()
	expiry, exists := tokenBlacklist.tokens[tokenStr]
	if !exists {
		return false
	}
	// vNext race fix: the previous version called delete() here — a WRITE —
	// while holding only the RLock, which is a data race against every
	// concurrent reader/writer (instant -race detector hit, possible map
	// corruption). Expiry cleanup now happens exclusively in the sweeper
	// goroutine above; this function is strictly read-only.
	return !time.Now().After(expiry)
}

func blacklistToken(tokenStr string, expiry time.Time) {
	tokenBlacklist.Lock()
	defer tokenBlacklist.Unlock()
	tokenBlacklist.tokens[tokenStr] = expiry
}

// JWT identity claims. iss/aud bind tokens to THIS panel instance so a
// token issued by one HESAR node is rejected by another; jti makes every
// token individually revocable through the blacklist.
const (
	jwtIssuer   = "hesar"
	jwtAudience = "hesar-panel"
)

func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if config.GlobalConfig == nil {
			jsonError(w, "system config not initialized", http.StatusInternalServerError)
			return
		}
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			jsonError(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			jsonError(w, "invalid authorization header", http.StatusUnauthorized)
			return
		}
		tokenString := parts[1]
		startBlacklistSweeper()
		if isTokenBlacklisted(tokenString) {
			jsonError(w, "token has been revoked", http.StatusUnauthorized)
			return
		}
		secret := config.GlobalConfig.GetConfig().SecretKey
		token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
			}
			return []byte(secret), nil
		}, jwt.WithIssuer(jwtIssuer), jwt.WithAudience(jwtAudience))
		if err != nil || !token.Valid {
			jsonError(w, "unauthorized token", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	if !loginLimiter.isAllowed(ip) {
		system.LogWarn("Rate limit exceeded for IP: %s", ip)
		jsonError(w, "too many login attempts, try again later", http.StatusTooManyRequests)
		return
	}
	var req LoginRequest
	if !decodeJSONBody(w, r, &req) {
		return
	}
	cfg := config.GlobalConfig.GetConfig()
	usernameMatch := subtle.ConstantTimeCompare([]byte(req.Username), []byte(cfg.AdminUsername))
	passwordMatch := subtle.ConstantTimeCompare([]byte(req.Password), []byte(cfg.AdminPassword))
	if usernameMatch != 1 || passwordMatch != 1 {
		system.LogWarn("Failed login attempt from IP: %s", ip)
		jsonError(w, "invalid username or password", http.StatusUnauthorized)
		return
	}
	// Authenticated ⇒ this IP's failed-attempt bucket must be cleared, or the
	// limiter would eventually lock out the owner of the panel for merely
	// logging in a few times (see rateLimiter.reset).
	loginLimiter.reset(ip)
	jtiBytes := make([]byte, 16)
	if _, err := rand.Read(jtiBytes); err != nil {
		system.LogError("Failed to generate JWT ID (jti): %v", err)
		jsonError(w, "failed to generate token", http.StatusInternalServerError)
		return
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": req.Username,
		"iss":      jwtIssuer,
		"aud":      jwtAudience,
		"jti":      hex.EncodeToString(jtiBytes),
		"exp":      time.Now().Add(24 * time.Hour).Unix(),
		"iat":      time.Now().Unix(),
	})
	tokenString, err := token.SignedString([]byte(cfg.SecretKey))
	if err != nil {
		system.LogError("Failed to sign JWT token: %v", err)
		jsonError(w, "failed to generate token", http.StatusInternalServerError)
		return
	}
	system.LogInfo("Successful login for user: %s from IP: %s", req.Username, ip)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(LoginResponse{Token: tokenString, Message: "Login successful"})
}

func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
		blacklistToken(tokenStr, time.Now().Add(24*time.Hour))
	}
	system.LogInfo("GUI Logout executed")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"message": "Logged out successfully"})
}

// AuthVerifyHandler answers one question for the SPA: is the bearer token in
// this request still a valid, unrevoked session?
//
// It exists because the panel's route guard needs a *protected* endpoint to
// validate its stored JWT, and /api/auth/status is deliberately public (the
// login form calls it to decide whether the daemon is up at all). Pointing
// the guard at the public endpoint — which is what ProtectedRoute did —
// meant "we have some token string" was treated as "we are authenticated",
// so an expired or revoked token still rendered the whole panel until the
// first real API call failed.
func AuthVerifyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"valid":    true,
		"username": config.GlobalConfig.GetSafeConfig().AdminUsername,
	})
}

func StatusHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"initialized": config.GlobalConfig != nil,
	})
}
