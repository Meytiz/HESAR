//go:build !linux

package tunnel

import (
	"context"
	"fmt"
	"net"

	"github.com/Meytiz/HESAR/backend/internal/config"
)

func underlayAddress(ctx context.Context, cfg *config.TunnelConfig) (net.IP, error) {
	if cfg.UnderlayInterface == "" {
		return nil, nil
	}
	return nil, fmt.Errorf("L3 underlay requires Linux")
}
