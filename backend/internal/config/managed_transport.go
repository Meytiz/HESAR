package config

import (
	"crypto/ecdh"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
)

// Managed carriers are typed operations, never user-supplied commands/config files.
func validateCarrier(t *TunnelConfig) error {
	switch t.Carrier {
	case "", "direct":
		for _, raw := range []string{t.CarrierPeerIP, t.CarrierLocalIP} {
			if raw == "" {
				continue
			}
			p := net.ParseIP(raw)
			if p == nil || p.To4() == nil || p.IsLoopback() || p.IsUnspecified() || p.IsMulticast() || p.IsLinkLocalUnicast() || p.To4()[0] >= 240 {
				return fmt.Errorf("optional WAN addresses must be unicast IPv4")
			}
		}
		return nil
	case "gre", "ipip", "paqet", "xray", "hysteria":
	default:
		return fmt.Errorf("unsupported managed carrier")
	}
	if t.UnderlayInterface != "" || t.ProxyURL != "" {
		return fmt.Errorf("managed carriers configure their own interface/proxy; clear manual overrides")
	}
	ip := net.ParseIP(t.CarrierPeerIP)
	if ip == nil || ip.To4() == nil || ip.IsLoopback() || ip.IsMulticast() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.To4()[0] >= 240 {
		return fmt.Errorf("carrier_peer_ip must be the other server's unicast IPv4")
	}
	if t.CarrierLocalIP != "" {
		p := net.ParseIP(t.CarrierLocalIP)
		if p == nil || p.To4() == nil || p.IsLoopback() || p.IsUnspecified() || p.IsMulticast() || p.IsLinkLocalUnicast() || p.To4()[0] >= 240 || p.Equal(ip) {
			return fmt.Errorf("invalid carrier_local_ip")
		}
	}
	if t.Carrier == "gre" || t.Carrier == "ipip" {
		if t.Protocol != "tcp" && t.Protocol != "quic" && t.Protocol != "kcp" {
			return fmt.Errorf("GRE/IPIP supports TCP, QUIC or KCP")
		}
		if !privateIPv4(t.CarrierLocalInner) || !privateIPv4(t.CarrierRemoteInner) || t.CarrierLocalInner == t.CarrierRemoteInner {
			return fmt.Errorf("two different private inner IPv4 addresses are required")
		}
		if t.CarrierMTU < 576 || t.CarrierMTU > 1480 || (t.Protocol == "quic" && t.CarrierMTU < 1228) {
			return fmt.Errorf("invalid carrier MTU (QUIC minimum 1228)")
		}
		return nil
	}
	if t.Protocol != "tcp" {
		return fmt.Errorf("managed external cores carry the authenticated TCP transport")
	}
	if t.CarrierPort == t.RemotePort {
		return fmt.Errorf("carrier public port and internal transport port must differ")
	}
	if t.CarrierPort < 1 || t.CarrierPort > 65535 || t.Carrier == "paqet" && t.CarrierPort < 1024 {
		return fmt.Errorf("carrier_port must be 1-65535; Paqet requires a dedicated port >=1024")
	}
	if t.Carrier == "paqet" || t.Carrier == "hysteria" {
		if len(t.CarrierAuth) < 32 || len(t.CarrierAuth) > 256 {
			return fmt.Errorf("carrier_auth must contain 32-256 characters")
		}
	}
	if t.Carrier == "hysteria" {
		if len(t.CarrierObfs) < 32 || len(t.CarrierObfs) > 256 || !validHost(t.ServerName) {
			return fmt.Errorf("hysteria requires an independent obfs key and TLS server name")
		}
		if t.Mode == "overseas" {
			if _, err := tls.X509KeyPair([]byte(t.TLSCertPEM), []byte(t.TLSKeyPEM)); err != nil {
				return fmt.Errorf("invalid Hysteria certificate/key PEM")
			}
		}
	}
	if t.Carrier == "xray" {
		if !validHost(t.ServerName) {
			return fmt.Errorf("REALITY requires a TLS cover server name")
		}
		key := t.RealityPublicKey
		if t.Mode == "overseas" {
			key = t.RealityPrivateKey
		}
		b, err := base64.RawURLEncoding.DecodeString(key)
		if err != nil || len(b) != 32 {
			return fmt.Errorf("invalid REALITY X25519 key")
		}
		if t.Mode == "overseas" {
			if _, err := ecdh.X25519().NewPrivateKey(b); err != nil {
				return fmt.Errorf("invalid REALITY private key")
			}
		}
		sid, err := hex.DecodeString(t.RealityShortID)
		if err != nil || len(sid) != 8 {
			return fmt.Errorf("REALITY short ID must be 16 hex characters")
		}
		if t.RealityTarget != "" {
			host, port, err := net.SplitHostPort(t.RealityTarget)
			number, portErr := strconv.Atoi(port)
			if err != nil || !validHost(host) || portErr != nil || number < 1 || number > 65535 {
				return fmt.Errorf("invalid REALITY cover target host:port")
			}
		}
	}
	return nil
}
