package tunnel

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"
)

func TestShapedRecordsRejectOversizedPeerFrame(t *testing.T) {
	for _, length := range []uint16{0, maxRecordPayload + 1} {
		a, b := net.Pipe()
		c := &paddedRecordConn{Conn: a}
		go func() {
			defer b.Close()
			var hdr [4]byte
			binary.BigEndian.PutUint16(hdr[:2], length)
			_, _ = b.Write(hdr[:])
		}()
		_, err := c.Read(make([]byte, 1))
		a.Close()
		if err == nil {
			t.Fatal("invalid frame accepted")
		}
	}
}
func TestShapedRecordsPreserveStreamBoundaries(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	left, right := &paddedRecordConn{Conn: a}, &paddedRecordConn{Conn: b}
	payload := bytes.Repeat([]byte("bounded-record"), 5000)
	errCh := make(chan error, 1)
	go func() { _, err := left.Write(payload); errCh <- err }()
	result := make([]byte, len(payload))
	if _, err := io.ReadFull(right, result); err != nil {
		t.Fatal(err)
	}
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(result, payload) {
		t.Fatal("stream changed")
	}
}
