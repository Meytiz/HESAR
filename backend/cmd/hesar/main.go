package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/Meytiz/HESAR/backend/internal/api"
	"github.com/Meytiz/HESAR/backend/internal/config"
	"github.com/Meytiz/HESAR/backend/internal/system"
	"github.com/Meytiz/HESAR/backend/internal/tunnel"
)

var (
	Version   = "1.1.9"
	BuildDate = "unknown"
)

func main() {
	configPath := flag.String("config", "data/config.json", "Path to configuration JSON")
	portOverride := flag.Int("port", 0, "Override GUI listen port")
	usernameOverride := flag.String("user", "", "Override GUI admin username")
	showVer := flag.Bool("version", false, "Display version and exit")
	flag.Parse()

	if *showVer {
		fmt.Printf("HESAR Reverse Tunnel Suite v%s (Built on %s)\n", Version, BuildDate)
		os.Exit(0)
	}

	if err := system.InitLogger("/var/log/hesar.log", 10); err != nil {
		fmt.Printf("[FATAL] Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}
	system.LogInfo("Starting HESAR Engine v%s...", Version)

	if err := config.InitGlobalConfig(*configPath); err != nil {
		system.LogError("Failed to initialize config: %v", err)
		os.Exit(1)
	}

	cfg := config.GlobalConfig.GetConfig()

	if *usernameOverride != "" {
		password := os.Getenv("HESAR_PASSWORD")
		if password == "" {
			password = cfg.AdminPassword
			system.LogWarn("No HESAR_PASSWORD env var. Keeping existing password.")
		}
		if err := config.GlobalConfig.UpdateSettings(*usernameOverride, password, "", 0); err != nil {
			system.LogError("Failed to apply credential overrides: %v", err)
			os.Exit(1)
		}
		system.LogInfo("GUI credentials updated via CLI/env override.")
	}

	cfg = config.GlobalConfig.GetConfig()
	listenPort := cfg.ListenPort
	if *portOverride > 0 {
		listenPort = *portOverride
	}
	if listenPort <= 0 || listenPort > 65535 {
		listenPort = 8080
		system.LogWarn("Invalid port. Defaulting to :%d", listenPort)
	}

	tunnel.StartConfiguredActiveTunnels()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	errCh := make(chan error, 1)
	go func() {
		errCh <- api.StartServer(ctx, listenPort)
	}()

	select {
	case sig := <-sigCh:
		system.LogInfo("Received signal: %v. Shutting down...", sig)
	case err := <-errCh:
		if err != nil {
			system.LogError("Server error: %v", err)
		}
	}

	cancel()
	tunnel.GlobalTunnelManager.StopAll()
	system.LogInfo("HESAR shut down gracefully.")
}