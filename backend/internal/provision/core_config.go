//go:build linux

package provision

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"path/filepath"
	"strconv"
)

func (a *agent) coreConfig(e *coreEntry, local, device, mac string, socks int) ([]byte, error) {
	c := e.cfg
	server := c.Mode == "overseas"
	proxy := fmt.Sprintf("127.0.0.1:%d", socks)
	peer := net.JoinHostPort(c.CarrierPeerIP, strconv.Itoa(c.CarrierPort))
	var out any
	switch c.Carrier {
	case "paqet":
		role, localPort := "client", 0
		if server {
			role = "server"
			localPort = c.CarrierPort
		}
		value := map[string]any{"role": role, "log": map[string]any{"level": "warn"}, "network": map[string]any{"interface": device, "ipv4": map[string]any{"addr": net.JoinHostPort(local, strconv.Itoa(localPort)), "router_mac": mac}, "tcp": map[string]any{"local_flag": []string{"PA"}, "remote_flag": []string{"PA"}}}, "transport": map[string]any{"protocol": "kcp", "conn": 1, "kcp": map[string]any{"mode": "normal", "mtu": 1200, "block": "aes", "key": c.CarrierAuth}}}
		if server {
			value["listen"] = map[string]any{"addr": ":" + strconv.Itoa(c.CarrierPort)}
		} else {
			value["socks5"] = []any{map[string]any{"listen": proxy}}
			value["server"] = map[string]any{"addr": peer}
		}
		out = value
	case "hysteria":
		value := map[string]any{"obfs": map[string]any{"type": "salamander", "salamander": map[string]any{"password": c.CarrierObfs}}}
		if server {
			if err := a.write(e.dir, "tls-cert.pem", []byte(c.TLSCertPEM), true); err != nil {
				return nil, err
			}
			if err := a.write(e.dir, "tls-key.pem", []byte(c.TLSKeyPEM), true); err != nil {
				return nil, err
			}
			value["listen"] = ":" + strconv.Itoa(c.CarrierPort)
			value["tls"] = map[string]any{"cert": filepath.Join(e.dir, "tls-cert.pem"), "key": filepath.Join(e.dir, "tls-key.pem")}
			value["auth"] = map[string]any{"type": "password", "password": c.CarrierAuth}
		} else {
			value["server"] = peer
			value["auth"] = c.CarrierAuth
			value["socks5"] = map[string]any{"listen": proxy}
			tls := map[string]any{"sni": c.ServerName, "insecure": false}
			if c.TLSCAPEM != "" {
				if err := a.write(e.dir, "tls-ca.pem", []byte(c.TLSCAPEM), true); err != nil {
					return nil, err
				}
				tls["ca"] = filepath.Join(e.dir, "tls-ca.pem")
			}
			value["tls"] = tls
		}
		out = value
	case "xray":
		hash := sha256.Sum256([]byte("HESAR_XRAY_UUID_v1:" + c.EncryptionKey))
		hash[6] = (hash[6] & 15) | 64
		hash[8] = (hash[8] & 63) | 128
		uuid := fmt.Sprintf("%x-%x-%x-%x-%x", hash[:4], hash[4:6], hash[6:8], hash[8:10], hash[10:16])
		pathHash := sha256.Sum256([]byte("HESAR_XHTTP_PATH_v1:" + c.EncryptionKey))
		path := fmt.Sprintf("/%x", pathHash[:16])
		value := map[string]any{"log": map[string]any{"loglevel": "warning"}}
		reality := map[string]any{"serverName": c.ServerName, "fingerprint": "chrome", "password": c.RealityPublicKey, "shortId": c.RealityShortID}
		if server {
			target := c.RealityTarget
			if target == "" {
				target = net.JoinHostPort(c.ServerName, "443")
			}
			reality = map[string]any{"target": target, "serverNames": []string{c.ServerName}, "privateKey": c.RealityPrivateKey, "shortIds": []string{c.RealityShortID}}
		}
		stream := map[string]any{"network": "xhttp", "security": "reality", "realitySettings": reality, "xhttpSettings": map[string]any{"path": path, "mode": "auto"}}
		if server {
			value["inbounds"] = []any{map[string]any{"listen": "0.0.0.0", "port": c.CarrierPort, "protocol": "vless", "settings": map[string]any{"clients": []any{map[string]any{"id": uuid}}, "decryption": "none"}, "streamSettings": stream}}
			allowed := map[string]any{"action": "allow", "network": "tcp", "ip": []string{"127.0.0.1/32"}, "port": strconv.Itoa(c.RemotePort)}
			value["outbounds"] = []any{map[string]any{"tag": "hesar", "protocol": "freedom", "settings": map[string]any{"finalRules": []any{allowed, map[string]any{"action": "block", "network": "tcp,udp", "blockDelay": "0"}}}}, map[string]any{"tag": "blocked", "protocol": "blackhole"}}
			value["routing"] = map[string]any{"rules": []any{map[string]any{"type": "field", "ip": []string{"127.0.0.1/32"}, "port": strconv.Itoa(c.RemotePort), "network": "tcp", "outboundTag": "hesar"}, map[string]any{"type": "field", "network": "tcp,udp", "outboundTag": "blocked"}}}
		} else {
			value["inbounds"] = []any{map[string]any{"listen": "127.0.0.1", "port": socks, "protocol": "socks", "settings": map[string]any{"auth": "noauth", "udp": false}}}
			value["outbounds"] = []any{map[string]any{"protocol": "vless", "settings": map[string]any{"vnext": []any{map[string]any{"address": c.CarrierPeerIP, "port": c.CarrierPort, "users": []any{map[string]any{"id": uuid, "encryption": "none"}}}}}, "streamSettings": stream}}
		}
		out = value
	default:
		return nil, fmt.Errorf("unsupported core")
	}
	return json.MarshalIndent(out, "", "  ")
}
