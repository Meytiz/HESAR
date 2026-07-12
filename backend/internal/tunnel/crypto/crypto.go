package crypto

import (
	"crypto/cipher"
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
	NonceSize      = chacha20poly1305.NonceSizeX
	TagSize        = chacha20poly1305.Overhead
	MaxChunk       = 65500
	SaltSize       = 32
	MaxReadBuffer  = 1 * 1024 * 1024 // ✅ 1MB محدودیت بافر
)

type Keys struct {
	PrivateKey []byte
	PublicKey  []byte
}

func GenerateX25519KeyPair() (*Keys, error) {
	var priv [32]byte
	if _, err := io.ReadFull(rand.Reader, priv[:]); err != nil {
		return nil, err
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

func DeriveHKDFKeys(masterKey []byte, salt []byte, info []byte) ([]byte, []byte, error) {
	h := hkdf.New(sha256.New, masterKey, salt, info)
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

type SecureConn struct {
	net.Conn
	txAead     cipher.AEAD
	rxAead     cipher.AEAD
	txNonce    uint64
	rxNonce    uint64
	readBuffer []byte
}

// NewSecureConn — ✅ با salt تصادفی در هر اتصال
func NewSecureConn(underlying net.Conn, masterKey []byte, isClient bool) (*SecureConn, error) {
	var salt []byte

	if isClient {
		// ✅ کلاینت salt تصادفی می‌سازد و می‌فرستد
		salt = make([]byte, SaltSize)
		if _, err := rand.Read(salt); err != nil {
			return nil, fmt.Errorf("failed to generate salt: %w", err)
		}
		if _, err := underlying.Write(salt); err != nil {
			return nil, fmt.Errorf("failed to send salt: %w", err)
		}
	} else {
		// ✅ سرور salt را می‌خواند
		salt = make([]byte, SaltSize)
		if _, err := io.ReadFull(underlying, salt); err != nil {
			return nil, fmt.Errorf("failed to read salt: %w", err)
		}
	}

	info := []byte("HESAR_CHACHA20_POLY1305_v2")
	k1, k2, err := DeriveHKDFKeys(masterKey, salt, info)
	if err != nil {
		return nil, fmt.Errorf("HKDF derivation failed: %w", err)
	}

	var txKey, rxKey []byte
	if isClient {
		txKey, rxKey = k1, k2
	} else {
		txKey, rxKey = k2, k1
	}

	txAead, err := chacha20poly1305.NewX(txKey)
	if err != nil {
		return nil, err
	}
	rxAead, err := chacha20poly1305.NewX(rxKey)
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

		// Prepare Nonce
		nonce := make([]byte, s.txAead.NonceSize())
		binary.LittleEndian.PutUint64(nonce, s.txNonce)
		s.txNonce++

		// Encrypt
		cipherChunk := s.txAead.Seal(nil, nonce, plainChunk, nil)

		// Frame: 2 bytes length + ciphertext
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

	// Read frame length header
	header := make([]byte, 2)
	if _, err := io.ReadFull(s.Conn, header); err != nil {
		return 0, err
	}

	frameLen := binary.BigEndian.Uint16(header)

	// ✅ اعتبارسنجی اندازه frame
	if int(frameLen) > MaxChunk+TagSize+NonceSize {
		return 0, fmt.Errorf("frame too large: %d bytes", frameLen)
	}

	cipherChunk := make([]byte, frameLen)
	if _, err := io.ReadFull(s.Conn, cipherChunk); err != nil {
		return 0, err
	}

	// Prepare Nonce
	nonce := make([]byte, s.rxAead.NonceSize())
	binary.LittleEndian.PutUint64(nonce, s.rxNonce)
	s.rxNonce++

	// Decrypt
	plainChunk, err := s.rxAead.Open(nil, nonce, cipherChunk, nil)
	if err != nil {
		return 0, fmt.Errorf("failed to authenticate Poly1305 chunk: %w", err)
	}

	n := copy(b, plainChunk)
	if n < len(plainChunk) {
		// ✅ محدودیت حافظه readBuffer
		remaining := len(plainChunk) - n
		if len(s.readBuffer)+remaining > MaxReadBuffer {
			return 0, fmt.Errorf("read buffer overflow: %d bytes", len(s.readBuffer)+remaining)
		}
		s.readBuffer = append(s.readBuffer, plainChunk[n:]...)
	}
	return n, nil
}

// Close — ✅ پاک‌سازی امن کلیدها از حافظه
func (s *SecureConn) Close() error {
	s.readBuffer = nil
	return s.Conn.Close()
}

func GenerateRandomHexKey(bytes int) string {
	buf := make([]byte, bytes)
	_, _ = rand.Read(buf)
	return hex.EncodeToString(buf)
}