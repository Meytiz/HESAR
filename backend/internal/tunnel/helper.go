package tunnel

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

var bufferPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 32*1024)
		return &b
	},
}

func ParsePorts(portsStr string) ([]int, error) {
	portsStr = strings.TrimSpace(portsStr)
	if portsStr == "" {
		return nil, errors.New("port configuration is empty")
	}
	parts := strings.Split(portsStr, ",")
	var result []int
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "-") {
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) != 2 {
				return nil, fmt.Errorf("invalid port range: %s", part)
			}
			start, err1 := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
			end, err2 := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
			if err1 != nil || err2 != nil || start > end || start < 1 || end > 65535 {
				return nil, fmt.Errorf("invalid port range: %s", part)
			}
			for p := start; p <= end; p++ {
				result = append(result, p)
			}
		} else {
			p, err := strconv.Atoi(part)
			if err != nil || p < 1 || p > 65535 {
				return nil, fmt.Errorf("invalid port: %s", part)
			}
			result = append(result, p)
		}
	}
	if len(result) == 0 {
		return nil, errors.New("no valid ports parsed")
	}
	seen := make(map[int]bool)
	var unique []int
	for _, p := range result {
		if !seen[p] {
			seen[p] = true
			unique = append(unique, p)
		}
	}
	return unique, nil
}

func copyWithIdleTimeout(dst, src net.Conn, timeout time.Duration) (int64, error) {
	bufp := bufferPool.Get().(*[]byte)
	defer bufferPool.Put(bufp)
	var written int64
	for {
		_ = src.SetReadDeadline(time.Now().Add(timeout))
		nr, er := src.Read(*bufp)
		if nr > 0 {
			nw, ew := dst.Write((*bufp)[0:nr])
			if nw > 0 {
				written += int64(nw)
			}
			if ew != nil {
				return written, ew
			}
		}
		if er != nil {
			return written, er
		}
	}
}

func ProxyBidirectional(c1, c2 net.Conn, onBytes func(in, out int64)) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		n, _ := copyWithIdleTimeout(c1, c2, 5*time.Minute)
		if tc, ok := c1.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
		if onBytes != nil {
			onBytes(n, 0)
		}
	}()

	go func() {
		defer wg.Done()
		n, _ := copyWithIdleTimeout(c2, c1, 5*time.Minute)
		if tc, ok := c2.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
		if onBytes != nil {
			onBytes(0, n)
		}
	}()

	wg.Wait()
	_ = c1.Close()
	_ = c2.Close()
}