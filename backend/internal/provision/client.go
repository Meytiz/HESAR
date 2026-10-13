// Package provision connects the unprivileged panel to the local network agent.
package provision

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/Meytiz/HESAR/backend/internal/config"
	"io"
	"net"
	"net/http"
	"os"
	"time"
)

const SocketPath = "/run/hesar-agent/control.sock"

func SocketAvailable() bool {
	path := os.Getenv("HESAR_AGENT_SOCKET")
	if path == "" {
		path = SocketPath
	}
	info, err := os.Stat(path)
	return err == nil && info.Mode()&os.ModeSocket != 0
}

type Request struct {
	Tunnel *config.TunnelConfig `json:"tunnel,omitempty"`
	ID     string               `json:"id,omitempty"`
}
type Runtime struct {
	ID      string `json:"id"`
	Carrier string `json:"carrier"`
	Running bool   `json:"running"`
	Error   string `json:"error,omitempty"`
}
type Reply struct {
	Tunnel    *config.TunnelConfig `json:"tunnel,omitempty"`
	Runtimes  []Runtime            `json:"runtimes,omitempty"`
	Available bool                 `json:"available"`
	Error     string               `json:"error,omitempty"`
	Warnings  []string             `json:"warnings,omitempty"`
	BBRActive bool                 `json:"bbr_active"`
}

func Call(ctx context.Context, path string, request Request) (Reply, error) {
	socket := os.Getenv("HESAR_AGENT_SOCKET")
	if socket == "" {
		socket = SocketPath
	}
	return CallSocket(ctx, socket, path, request)
}
func CallSocket(ctx context.Context, socket, path string, request Request) (Reply, error) {
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 45 * time.Second}
	data, err := json.Marshal(request)
	if err != nil {
		return Reply{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://agent/v1/"+path, bytes.NewReader(data))
	if err != nil {
		return Reply{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	response, err := client.Do(req)
	if err != nil {
		return Reply{}, fmt.Errorf("local network agent unavailable; install the complete GitHub release: %w", err)
	}
	defer response.Body.Close()
	var reply Reply
	if err := json.NewDecoder(io.LimitReader(response.Body, 512<<10)).Decode(&reply); err != nil {
		return reply, fmt.Errorf("invalid network agent response")
	}
	if response.StatusCode != http.StatusOK || reply.Error != "" {
		return reply, fmt.Errorf("network agent: %s", reply.Error)
	}
	return reply, nil
}
