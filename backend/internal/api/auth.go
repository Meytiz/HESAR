package api

import (
	"crypto/subtle"
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
	rl.attempts[ip] = recent
	if len(recent) >= rl.max {
		return false
	}
	rl.attempts[ip] = append(rl.attempts[ip], now)
	return true
}

var tokenBlacklist = struct {
	sync.RWMutex
	tokens map[string]time.Time
}{tokens: make(map[string]time.Time)}

func isTokenBlacklisted(tokenStr string) bool {
	tokenBlacklist.RLock()
	defer tokenBlacklist.RUnlock()
	expiry, exists := tokenBlacklist.tokens[tokenStr]
	if !exists {
		return false
	}
	if time.Now().After(expiry) {
		delete(tokenBlacklist.tokens, tokenStr)
		return false
	}
	return true
}

func blacklistToken(tokenStr string, expiry time.Time) {
	tokenBlacklist.Lock()
	defer tokenBlacklist.Unlock()
	tokenBlacklist.tokens[tokenStr] = expiry
}

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
		})
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
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request", http.StatusBadRequest)
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
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": req.Username,
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

func StatusHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"initialized": config.GlobalConfig != nil,
	})
}