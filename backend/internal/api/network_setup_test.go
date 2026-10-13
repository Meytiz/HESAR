package api

import (
	"bytes"
	"crypto/ecdh"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http/httptest"
	"testing"
)

func TestGeneratedTransportCredentials(t *testing.T) {
	w := httptest.NewRecorder()
	NetworkKeysHandler(w, httptest.NewRequest("POST", "/api/network/keys", bytes.NewBufferString(`{"server_name":"hesar.internal"}`)))
	if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal(w.Code)
	}
	var keys map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &keys); err != nil {
		t.Fatal(err)
	}
	if _, err := tls.X509KeyPair([]byte(keys["tls_cert_pem"]), []byte(keys["tls_key_pem"])); err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(keys["tls_cert_pem"]))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil || cert.VerifyHostname("hesar.internal") != nil {
		t.Fatal("invalid generated SAN")
	}
	raw, err := base64.RawURLEncoding.DecodeString(keys["reality_private_key"])
	if err != nil {
		t.Fatal(err)
	}
	private, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	if base64.RawURLEncoding.EncodeToString(private.PublicKey().Bytes()) != keys["reality_public_key"] || keys["carrier_auth"] == keys["carrier_obfs"] {
		t.Fatal("incorrect key material")
	}
}
