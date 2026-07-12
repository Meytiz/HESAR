package api

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"strings"
	"time"

	"github.com/Meytiz/HESAR/backend/internal/config"
	"github.com/Meytiz/HESAR/backend/internal/system"
	"github.com/golang-jwt/jwt/v5"
)

//go:embed dist/*
var staticFiles embed.FS

func jsonError(w http.ResponseWriter, message string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}

func StartServer(ctx context.Context, port int) error {
	distFS, err := fs.Sub(staticFiles, "dist")
	if err != nil {
		return fmt.Errorf("failed to load embedded dist: %w", err)
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/api/auth/status", StatusHandler)
	mux.HandleFunc("/api/auth/login", LoginHandler)
	mux.HandleFunc("/api/auth/logout", LogoutHandler)

	mux.Handle("/api/config", AuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			ConfigGetHandler(w, r)
		case http.MethodPost:
			ConfigUpdateHandler(w, r)
		default:
			jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})))

	mux.Handle("/api/tunnels", AuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			TunnelsListHandler(w, r)
		case http.MethodPost:
			TunnelSaveHandler(w, r)
		default:
			jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})))

	mux.Handle("/api/tunnels/", AuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		switch {
		case strings.HasSuffix(path, "/start"):
			TunnelStartHandler(w, r)
		case strings.HasSuffix(path, "/stop"):
			TunnelStopHandler(w, r)
		case r.Method == http.MethodDelete:
			TunnelDeleteHandler(w, r)
		default:
			jsonError(w, "not found", http.StatusNotFound)
		}
	})))

	mux.Handle("/api/stats", AuthMiddleware(http.HandlerFunc(StatsGetHandler)))
	mux.Handle("/api/optimize", AuthMiddleware(http.HandlerFunc(OptimizeExecHandler)))
	mux.Handle("/api/tester/sni", AuthMiddleware(http.HandlerFunc(TesterSNIHandler)))
	mux.Handle("/api/tester/ip", AuthMiddleware(http.HandlerFunc(TesterIPHandler)))
	mux.Handle("/api/keygen", AuthMiddleware(http.HandlerFunc(KeyGenHandler)))

	mux.HandleFunc("/api/logs", func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("token")
		if token == "" {
			jsonError(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		secret := config.GlobalConfig.GetConfig().SecretKey
		parsedToken, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
			}
			return []byte(secret), nil
		})
		if err != nil || !parsedToken.Valid {
			jsonError(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		LogsWebSocketHandler(w, r)
	})

	fileServer := http.FileServer(http.FS(distFS))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			jsonError(w, "not found", http.StatusNotFound)
			return
		}
		cleanedPath := strings.TrimPrefix(r.URL.Path, "/")
		if cleanedPath == "" {
			cleanedPath = "index.html"
		}
		_, openErr := distFS.Open(cleanedPath)
		if openErr != nil {
			r.URL.Path = "/"
			w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		fileServer.ServeHTTP(w, r)
	})

	server := &http.Server{
		Addr:         fmt.Sprintf("0.0.0.0:%d", port),
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		<-ctx.Done()
		system.LogInfo("Shutting down HTTP server...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	system.LogInfo("GUI Web Server listening on http://0.0.0.0:%d", port)
	return server.ListenAndServe()
}