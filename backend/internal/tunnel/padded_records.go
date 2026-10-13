package tunnel

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
)

const maxRecordPayload = 16 * 1024
const maxRecordPadding = 1152

// Shaped WSS v1 normalizes small writes into bounded length buckets. TLS and
// the existing authenticated AEAD remain responsible for security. This does
// not imitate a browser or claim immunity to traffic analysis.
type paddedRecordConn struct {
	net.Conn
	readMu, writeMu sync.Mutex
	pending         []byte
}

func (c *paddedRecordConn) Read(b []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if len(b) == 0 {
		return 0, nil
	}
	if len(c.pending) == 0 {
		var header [4]byte
		if _, err := io.ReadFull(c.Conn, header[:]); err != nil {
			return 0, err
		}
		payload, padding := int(binary.BigEndian.Uint16(header[:2])), int(binary.BigEndian.Uint16(header[2:]))
		if payload == 0 || payload > maxRecordPayload || padding > maxRecordPadding {
			return 0, fmt.Errorf("invalid shaped record bounds")
		}
		frame := make([]byte, payload+padding)
		if _, err := io.ReadFull(c.Conn, frame); err != nil {
			return 0, err
		}
		c.pending = frame[:payload]
	}
	n := copy(b, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}
func (c *paddedRecordConn) Write(b []byte) (written int, err error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	for len(b) > 0 {
		n := len(b)
		if n > maxRecordPayload {
			n = maxRecordPayload
		}
		target := ((n + 1023) / 1024) * 1024
		if n <= 256 {
			target = 512
		}
		var random [1]byte
		if _, err = rand.Read(random[:]); err != nil {
			return written, err
		}
		padding := target - n + int(random[0]&127)
		frame := make([]byte, 4+n+padding)
		binary.BigEndian.PutUint16(frame[:2], uint16(n))
		binary.BigEndian.PutUint16(frame[2:4], uint16(padding))
		copy(frame[4:], b[:n])
		if _, err = rand.Read(frame[4+n:]); err != nil {
			return written, err
		}
		for offset := 0; offset < len(frame); {
			count, e := c.Conn.Write(frame[offset:])
			if e != nil {
				return written, e
			}
			if count == 0 {
				return written, io.ErrShortWrite
			}
			offset += count
		}
		written += n
		b = b[n:]
	}
	return written, nil
}
func (c *paddedRecordConn) CloseWrite() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if closer, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return closer.CloseWrite()
	}
	return fmt.Errorf("underlying carrier has no half-close")
}
func shapeWSS(c net.Conn, cfgProtocol string) net.Conn {
	if cfgProtocol == "wss-shaped" {
		return &paddedRecordConn{Conn: c}
	}
	return c
}
