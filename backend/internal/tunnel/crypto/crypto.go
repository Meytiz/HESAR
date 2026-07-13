package crypto

import (
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const (
	// NonceSize/TagSize now match the STANDARD (non-X) ChaCha20-Poly1305
	// construction: a 12-byte (96-bit) nonce. The previous implementation
	// used chacha20poly1305.NewX (192-bit XChaCha20 nonce, intended for
	// randomly-generated nonces with no coordination between sender and
	// receiver) but only ever filled the first 8 bytes with a monotonic
	// counter, leaving the remaining 16 bytes permanently zero. That
	// wasted XChaCha20's actual benefit (safe random nonces) while adding
	// unnecessary per-packet overhead (a larger nonce derivation step)
	// for no security gain, since uniqueness was already guaranteed by
	// the counter alone.
	//
	// The standard 96-bit-nonce variant is the textbook construction for
	// exactly this "fixed key per direction + monotonically increasing
	// counter" pattern — the same approach TLS 1.3 uses for its record
	// layer. A uint64 counter fits directly in the first 8 bytes with
	// the remaining 4 bytes zero-padded, and per-direction session keys
	// (derived fresh per connection via the X25519 handshake above) make
	// counter reuse across connections impossible by construction.
	NonceSize     = chacha20poly1305.NonceSize
	TagSize       = chacha20poly1305.Overhead
	MaxChunk      = 65500
	SaltSize      = 32
	MaxReadBuffer = 1 * 1024 * 1024

	hsRandomSize = 16
	hsMacSize    = sha256.Size
	hsMsgSize    = 32 + hsRandomSize + hsMacSize
)

// Domain-separated HMAC labels and HKDF info string. "_v4" reflects the
// switch from XChaCha20-Poly1305 to standard ChaCha20-Poly1305 for the
// data channel AEAD; the handshake construction itself (X25519 ECDH +
// HMAC authentication + HKDF) is unchanged from _v3. Bumping this string
// is required so a node running the old build cannot silently
// misinterpret ciphertext framed for the wrong nonce size — both ends of
// a tunnel must run a matching version.
var (
	hsDomainMsg1 = []byte("HESAR_HS_MSG1_v3")
	hsDomainMsg2 = []byte("HESAR_HS_MSG2_v3")
	hsInfo       = []byte("HESAR_CHACHA20_POLY1305_v4_STDNONCE")
)

type Keys struct {
	PrivateKey []byte
	PublicKey  []byte
}

func GenerateX25519KeyPair() (*Keys, error) {
	var priv [32]byte
	if _, err := io.ReadFull(rand.Reader, priv[:]); err != nil {
		return nil, fmt.Errorf("crypto/rand read failed: %w", err)
	}
	var pub [32]byte
	curve25519.ScalarBaseMult(&pub, &priv)

	return &Keys{
		PrivateKey: priv[:],
		PublicKey:  pub[:],
	}, nil
}

func ComputeX25519SharedSecret(privateKey, peerPublicKey []byte) ([]byte, error) {
	if len(privateKey) != 32 || len(peerPublicKey) != 32 {
		return nil, errors.New("invalid key length, must be 32 bytes")
	}
	var priv, peerPub, shared [32]byte
	copy(priv[:], privateKey)
	copy(peerPub[:], peerPublicKey)

	curve25519.ScalarMult(&shared, &priv, &peerPub)
	return shared[:], nil
}

func DeriveHKDFKeys(ikm []byte, salt []byte, info []byte) ([]byte, []byte, error) {
	h := hkdf.New(sha256.New, ikm, salt, info)
	txKey := make([]byte, chacha20poly1305.KeySize)
	rxKey := make([]byte, chacha20poly1305.KeySize)

	if _, err := io.ReadFull(h, txKey); err != nil {
		return nil, nil, err
	}
	if _, err := io.ReadFull(h, rxKey); err != nil {
		return nil, nil, err
	}
	return txKey, rxKey, nil
}

func computeHMAC(key []byte, parts ...[]byte) []byte {
	mac := hmac.New(sha256.New, key)
	for _, p := range parts {
		mac.Write(p)
	}
	return mac.Sum(nil)
}

func isAllZero(b []byte) bool {
	var v byte
	for _, x := range b {
		v |= x
	}
	return v == 0
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func performClientHandshake(conn net.Conn, psk []byte) (txKey, rxKey []byte, err error) {
	ephKeys, err := GenerateX25519KeyPair()
	if err != nil {
		return nil, nil, fmt.Errorf("generate ephemeral keypair: %w", err)
	}
	defer zero(ephKeys.PrivateKey)

	randC := make([]byte, hsRandomSize)
	if _, err := io.ReadFull(rand.Reader, randC); err != nil {
		return nil, nil, fmt.Errorf("generate client random: %w", err)
	}

	mac1 := computeHMAC(psk, hsDomainMsg1, ephKeys.PublicKey, randC)
	msg1 := make([]byte, 0, hsMsgSize)
	msg1 = append(msg1, ephKeys.PublicKey...)
	msg1 = append(msg1, randC...)
	msg1 = append(msg1, mac1...)

	if _, err := conn.Write(msg1); err != nil {
		return nil, nil, fmt.Errorf("write handshake msg1: %w", err)
	}

	msg2 := make([]byte, hsMsgSize)
	if _, err := io.ReadFull(conn, msg2); err != nil {
		return nil, nil, fmt.Errorf("read handshake msg2: %w", err)
	}
	ephPubS := msg2[0:32]
	randS := msg2[32 : 32+hsRandomSize]
	mac2Received := msg2[32+hsRandomSize:]

	expectedMac2 := computeHMAC(psk, hsDomainMsg2, ephPubS, randS, ephKeys.PublicKey, randC)
	if !hmac.Equal(mac2Received, expectedMac2) {
		return nil, nil, errors.New("handshake authentication failed: invalid server MAC (wrong pre-shared key or MITM attempt)")
	}

	shared, err := ComputeX25519SharedSecret(ephKeys.PrivateKey, ephPubS)
	if err != nil {
		return nil, nil, fmt.Errorf("compute shared secret: %w", err)
	}
	defer zero(shared)

	if isAllZero(shared) {
		return nil, nil, errors.New("handshake failed: degenerate shared secret (invalid peer public key)")
	}

	ikm := make([]byte, 0, len(shared)+len(psk))
	ikm = append(ikm, shared...)
	ikm = append(ikm, psk...)
	defer zero(ikm)

	salt := make([]byte, 0, hsRandomSize*2)
	salt = append(salt, randC...)
	salt = append(salt, randS...)

	k1, k2, err := DeriveHKDFKeys(ikm, salt, hsInfo)
	if err != nil {
		return nil, nil, fmt.Errorf("HKDF derivation failed: %w", err)
	}
	return k1, k2, nil
}

func performServerHandshake(conn net.Conn, psk []byte) (txKey, rxKey []byte, err error) {
	msg1 := make([]byte, hsMsgSize)
	if _, err := io.ReadFull(conn, msg1); err != nil {
		return nil, nil, fmt.Errorf("read handshake msg1: %w", err)
	}
	ephPubC := msg1[0:32]
	randC := msg1[32 : 32+hsRandomSize]
	mac1Received := msg1[32+hsRandomSize:]

	expectedMac1 := computeHMAC(psk, hsDomainMsg1, ephPubC, randC)
	if !hmac.Equal(mac1Received, expectedMac1) {
		return nil, nil, errors.New("handshake authentication failed: invalid client MAC (wrong pre-shared key or MITM attempt)")
	}

	ephKeys, err := GenerateX25519KeyPair()
	if err != nil {
		return nil, nil, fmt.Errorf("generate ephemeral keypair: %w", err)
	}
	defer zero(ephKeys.PrivateKey)

	randS := make([]byte, hsRandomSize)
	if _, err := io.ReadFull(rand.Reader, randS); err != nil {
		return nil, nil, fmt.Errorf("generate server random: %w", err)
	}

	mac2 := computeHMAC(psk, hsDomainMsg2, ephKeys.PublicKey, randS, ephPubC, randC)
	msg2 := make([]byte, 0, hsMsgSize)
	msg2 = append(msg2, ephKeys.PublicKey...)
	msg2 = append(msg2, randS...)
	msg2 = append(msg2, mac2...)

	if _, err := conn.Write(msg2); err != nil {
		return nil, nil, fmt.Errorf("write handshake msg2: %w", err)
	}

	shared, err := ComputeX25519SharedSecret(ephKeys.PrivateKey, ephPubC)
	if err != nil {
		return nil, nil, fmt.Errorf("compute shared secret: %w", err)
	}
	defer zero(shared)

	if isAllZero(shared) {
		return nil, nil, errors.New("handshake failed: degenerate shared secret (invalid peer public key)")
	}

	ikm := make([]byte, 0, len(shared)+len(psk))
	ikm = append(ikm, shared...)
	ikm = append(ikm, psk...)
	defer zero(ikm)

	salt := make([]byte, 0, hsRandomSize*2)
	salt = append(salt, randC...)
	salt = append(salt, randS...)

	k1, k2, err := DeriveHKDFKeys(ikm, salt, hsInfo)
	if err != nil {
		return nil, nil, fmt.Errorf("HKDF derivation failed: %w", err)
	}
	return k2, k1, nil
}

type SecureConn struct {
	net.Conn
	txAead     cipher.AEAD
	rxAead     cipher.AEAD
	txNonce    uint64
	rxNonce    uint64
	readBuffer []byte
}

// NewSecureConn performs a mutual, PSK-authenticated ephemeral X25519
// handshake over `underlying`, then wraps it with per-direction standard
// ChaCha20-Poly1305 AEAD (96-bit nonce, monotonic counter) using the
// derived session keys.
func NewSecureConn(underlying net.Conn, presharedKey []byte, isClient bool) (*SecureConn, error) {
	var txKey, rxKey []byte
	var err error

	if isClient {
		txKey, rxKey, err = performClientHandshake(underlying, presharedKey)
	} else {
		txKey, rxKey, err = performServerHandshake(underlying, presharedKey)
	}
	if err != nil {
		return nil, fmt.Errorf("secure handshake failed: %w", err)
	}
	defer zero(txKey)
	defer zero(rxKey)

	// chacha20poly1305.New (standard, 12-byte nonce) replaces the
	// previous NewX (XChaCha20, 24-byte nonce). This is the correct
	// primitive for a fixed-key-per-direction + monotonic-counter nonce
	// scheme: the counter alone guarantees nonce uniqueness for the
	// lifetime of a single derived session key, which is itself fresh
	// per connection (forward secrecy via the X25519 handshake above) —
	// so there is never a scenario where the same (key, nonce) pair
	// could repeat. XChaCha20's extended nonce exists specifically to
	// allow safe *random* nonce generation without a shared counter,
	// which was never actually exercised here.
	txAead, err := chacha20poly1305.New(txKey)
	if err != nil {
		return nil, err
	}
	rxAead, err := chacha20poly1305.New(rxKey)
	if err != nil {
		return nil, err
	}

	return &SecureConn{
		Conn:       underlying,
		txAead:     txAead,
		rxAead:     rxAead,
		readBuffer: make([]byte, 0),
	}, nil
}

func (s *SecureConn) Write(b []byte) (int, error) {
	totalWritten := 0
	for len(b) > 0 {
		chunkSize := len(b)
		if chunkSize > MaxChunk {
			chunkSize = MaxChunk
		}

		plainChunk := b[:chunkSize]
		b = b[chunkSize:]

		// Nonce buffer is sized dynamically from the AEAD's own
		// NonceSize() (12 bytes for standard ChaCha20-Poly1305). The
		// first 8 bytes carry the little-endian monotonic counter; the
		// remaining 4 bytes stay zero — there is no free entropy to put
		// there, and none is needed: uniqueness comes entirely from the
		// counter plus the per-connection, per-direction session key.
		nonce := make([]byte, s.txAead.NonceSize())
		binary.LittleEndian.PutUint64(nonce, s.txNonce)
		s.txNonce++

		cipherChunk := s.txAead.Seal(nil, nonce, plainChunk, nil)

		header := make([]byte, 2)
		binary.BigEndian.PutUint16(header, uint16(len(cipherChunk)))

		if _, err := s.Conn.Write(header); err != nil {
			return totalWritten, err
		}
		if _, err := s.Conn.Write(cipherChunk); err != nil {
			return totalWritten, err
		}

		totalWritten += chunkSize
	}
	return totalWritten, nil
}

func (s *SecureConn) Read(b []byte) (int, error) {
	if len(s.readBuffer) > 0 {
		n := copy(b, s.readBuffer)
		s.readBuffer = s.readBuffer[n:]
		return n, nil
	}

	header := make([]byte, 2)
	if _, err := io.ReadFull(s.Conn, header); err != nil {
		return 0, err
	}

	frameLen := binary.BigEndian.Uint16(header)

	if int(frameLen) > MaxChunk+TagSize+NonceSize {
		return 0, fmt.Errorf("frame too large: %d bytes", frameLen)
	}

	cipherChunk := make([]byte, frameLen)
	if _, err := io.ReadFull(s.Conn, cipherChunk); err != nil {
		return 0, err
	}

	nonce := make([]byte, s.rxAead.NonceSize())
	binary.LittleEndian.PutUint64(nonce, s.rxNonce)
	s.rxNonce++

	plainChunk, err := s.rxAead.Open(nil, nonce, cipherChunk, nil)
	if err != nil {
		return 0, fmt.Errorf("failed to authenticate Poly1305 chunk: %w", err)
	}

	n := copy(b, plainChunk)
	if n < len(plainChunk) {
		remaining := len(plainChunk) - n
		if len(s.readBuffer)+remaining > MaxReadBuffer {
			return 0, fmt.Errorf("read buffer overflow: %d bytes", len(s.readBuffer)+remaining)
		}
		s.readBuffer = append(s.readBuffer, plainChunk[n:]...)
	}
	return n, nil
}

func (s *SecureConn) Close() error {
	zero(s.readBuffer)
	s.readBuffer = nil
	return s.Conn.Close()
}

// GenerateRandomHexKey reads `bytes` cryptographically secure random
// bytes and returns them hex-encoded. The error from rand.Read is
// propagated instead of discarded.
func GenerateRandomHexKey(bytes int) (string, error) {
	buf := make([]byte, bytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("crypto/rand read failed: %w", err)
	}
	return hex.EncodeToString(buf), nil
}