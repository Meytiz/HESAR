//go:build linux

package tunnel

import (
	"context"
	"fmt"
	"net"

	"github.com/Meytiz/HESAR/backend/internal/config"
)

// L3 links are provisioned by a separate administrator-owned helper. The
// daemon never changes routes, firewall rules or network capabilities.
func underlayAddress(ctx context.Context, cfg *config.TunnelConfig) (net.IP, error) {
	if cfg.UnderlayInterface == "" {
		return nil, nil
	}
	iface, err := net.InterfaceByName(cfg.UnderlayInterface)
	if err != nil || iface.Flags&net.FlagUp == 0 {
		return nil, fmt.Errorf("L3 interface %q is unavailable or down", cfg.UnderlayInterface)
	}
	if cfg.Protocol == ProtocolQUIC && iface.MTU < 1228 {
		return nil, fmt.Errorf("L3 QUIC requires interface MTU >= 1228 for a 1200-byte UDP payload")
	}
	if iface.MTU < 576 {
		return nil, fmt.Errorf("L3 interface MTU must be at least 576")
	}
	addresses, err := iface.Addrs()
	if err != nil {
		return nil, fmt.Errorf("L3 addresses: %w", err)
	}
	var source net.IP
	for _, address := range addresses {
		ip, _, err := net.ParseCIDR(address.String())
		if err == nil && ip.To4() != nil && ip.IsPrivate() {
			if source != nil {
				return nil, fmt.Errorf("L3 interface must have exactly one private IPv4 address")
			}
			source = ip.To4()
		}
	}
	if source == nil {
		return nil, fmt.Errorf("L3 interface has no private IPv4 address")
	}
	if cfg.Mode == "overseas" {
		if !source.Equal(net.ParseIP(cfg.ListenAddress)) {
			return nil, fmt.Errorf("L3 listener address is not assigned to the selected interface")
		}
	} else {
		peer := net.ParseIP(cfg.RemoteIP)
		if peer == nil || peer.To4() == nil || source.Equal(peer) {
			return nil, fmt.Errorf("invalid L3 peer address")
		}
		if err := checkUnderlayRoute(ctx, source, peer, iface.Index); err != nil {
			return nil, fmt.Errorf("L3 route validation failed: %w", err)
		}
	}
	return source, nil
}
