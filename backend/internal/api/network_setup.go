package api

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"github.com/Meytiz/HESAR/backend/internal/config"
	"github.com/Meytiz/HESAR/backend/internal/provision"
	"math/big"
	"net"
	"net/http"
	"strings"
	"time"
)

const storedSecret = "<stored>"

func redactTransportSecrets(t *config.TunnelConfig) {
	t.EncryptionKey = maskKey(t.EncryptionKey)
	for _, p := range []*string{&t.CarrierAuth, &t.CarrierObfs, &t.RealityPrivateKey, &t.TLSKeyPEM} {
		if *p != "" {
			*p = storedSecret
		}
	}
}
func preserveTransportSecrets(t, previous *config.TunnelConfig) {
	for _, pair := range [][2]*string{{&t.CarrierAuth, &previous.CarrierAuth}, {&t.CarrierObfs, &previous.CarrierObfs}, {&t.RealityPrivateKey, &previous.RealityPrivateKey}, {&t.TLSKeyPEM, &previous.TLSKeyPEM}} {
		if *pair[0] == storedSecret {
			*pair[0] = *pair[1]
		}
	}
}
func NetworkRuntimeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, "GET required", 405)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	reply, err := provision.Call(ctx, "status", provision.Request{})
	if err != nil {
		_ = jsonEncode(w, map[string]any{"available": false, "runtimes": []any{}, "message": "Managed transports require the network agent from the complete Linux release."})
		return
	}
	_ = jsonEncode(w, reply)
}
func NetworkKeysHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "POST required", 405)
		return
	}
	var request struct {
		ServerName string `json:"server_name"`
	}
	if !decodeJSONBody(w, r, &request) {
		return
	}
	name := request.ServerName
	if name == "" {
		name = "hesar.internal"
	}
	if len(name) > 253 || net.ParseIP(name) == nil && !validCertificateName(name) {
		jsonError(w, "invalid TLS server name", 400)
		return
	}
	xkey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		jsonError(w, "key generation failed", 500)
		return
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		jsonError(w, "TLS key generation failed", 500)
		return
	}
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		jsonError(w, "serial generation failed", 500)
		return
	}
	cert := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: name}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(90 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
	if ip := net.ParseIP(name); ip != nil {
		cert.IPAddresses = []net.IP{ip}
	} else {
		cert.DNSNames = []string{name}
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		jsonError(w, "certificate generation failed", 500)
		return
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		jsonError(w, "key encoding failed", 500)
		return
	}
	random := make([]byte, 72)
	if _, err := rand.Read(random); err != nil {
		jsonError(w, "random generation failed", 500)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = jsonEncode(w, map[string]string{"carrier_auth": hex.EncodeToString(random[:32]), "carrier_obfs": hex.EncodeToString(random[32:64]), "reality_private_key": base64.RawURLEncoding.EncodeToString(xkey.Bytes()), "reality_public_key": base64.RawURLEncoding.EncodeToString(xkey.PublicKey().Bytes()), "reality_short_id": hex.EncodeToString(random[64:]), "tls_cert_pem": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), "tls_key_pem": string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})), "server_name": name})
}
func validCertificateName(name string) bool {
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
	}
	for _, c := range name {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '.') {
			return false
		}
	}
	return len(name) > 0
}
func NetworkPeerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "POST required", 405)
		return
	}
	var request struct {
		ID string `json:"id"`
	}
	if !decodeJSONBody(w, r, &request) {
		return
	}
	original, err := config.GlobalConfig.GetTunnel(request.ID)
	if err != nil {
		writeConfigError(w, err)
		return
	}
	if original.Mode != "overseas" {
		jsonError(w, "Export peer setup from the overseas node", 400)
		return
	}
	local := original.CarrierLocalIP
	if local == "" {
		hint := original.CarrierPeerIP
		if hint == "" {
			hint = "1.1.1.1"
		} // Local route lookup; UDP connect sends no packet.
		c, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.ParseIP(hint), Port: 9})
		if err == nil {
			local = c.LocalAddr().(*net.UDPAddr).IP.String()
			c.Close()
		}
	}
	if local == "" {
		local = original.ServerName
	}
	if local == "" {
		jsonError(w, "Enter this server's IPv4 before exporting peer setup", 400)
		return
	}
	peer := *original
	peer.ID = ""
	peer.Name = original.Name + " / Iran"
	peer.Status = "inactive"
	peer.Mode = "iran"
	peer.LocalPorts = "18080"
	peer.ListenAddress = ""
	peer.UnderlayInterface = ""
	peer.ProxyURL = ""
	peer.RemoteIP = local
	if ip := net.ParseIP(local); ip != nil && ip.To4() != nil {
		peer.CarrierPeerIP = local
	} else {
		peer.CarrierPeerIP = ""
	}
	peer.CarrierLocalIP = original.CarrierPeerIP
	peer.CarrierLocalInner, peer.CarrierRemoteInner = original.CarrierRemoteInner, original.CarrierLocalInner
	peer.TLSCAPEM = original.TLSCertPEM
	peer.TLSKeyPEM = ""
	peer.TLSCertPEM = ""
	peer.TLSCertFile = ""
	peer.TLSKeyFile = ""
	peer.TLSCAFile = ""
	if original.Carrier == "xray" {
		raw, e := base64.RawURLEncoding.DecodeString(original.RealityPrivateKey)
		if e != nil {
			jsonError(w, "invalid REALITY key", 400)
			return
		}
		key, e := ecdh.X25519().NewPrivateKey(raw)
		if e != nil {
			jsonError(w, "invalid REALITY key", 400)
			return
		}
		peer.RealityPublicKey = base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
	}
	peer.RealityPrivateKey = ""
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = jsonEncode(w, map[string]any{"version": 1, "tunnel": peer, "notice": fmt.Sprintf("Contains private peer credentials for %s; import only into your Iran panel.", original.Name)})
}
