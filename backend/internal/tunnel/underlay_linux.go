//go:build linux

package tunnel

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Query the kernel's policy route for the actual source/destination pair.
// Route dumping or checking only the main table would miss source rules.
func checkUnderlayRoute(ctx context.Context, source, peer net.IP, index int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	timeout := time.Second
	if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) < timeout {
		timeout = time.Until(deadline)
	}
	if timeout <= 0 {
		return context.DeadlineExceeded
	}
	tv := unix.NsecToTimeval(timeout.Nanoseconds())
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		return err
	}
	request := make([]byte, 44)
	binary.NativeEndian.PutUint32(request[:4], uint32(len(request)))
	binary.NativeEndian.PutUint16(request[4:6], unix.RTM_GETROUTE)
	binary.NativeEndian.PutUint16(request[6:8], unix.NLM_F_REQUEST)
	binary.NativeEndian.PutUint32(request[8:12], 1)
	request[16], request[17], request[18] = unix.AF_INET, 32, 32
	for i, attr := range []struct {
		kind uint16
		ip   net.IP
	}{{unix.RTA_DST, peer}, {unix.RTA_SRC, source}} {
		offset := 28 + i*8
		binary.NativeEndian.PutUint16(request[offset:offset+2], 8)
		binary.NativeEndian.PutUint16(request[offset+2:offset+4], attr.kind)
		copy(request[offset+4:offset+8], attr.ip.To4())
	}
	if err := unix.Sendto(fd, request, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	buffer := make([]byte, 8192)
	n, sender, err := unix.Recvfrom(fd, buffer, 0)
	if err != nil {
		return err
	}
	address, ok := sender.(*unix.SockaddrNetlink)
	if !ok || address.Pid != 0 {
		return fmt.Errorf("route response is not from the kernel")
	}
	messages, err := syscall.ParseNetlinkMessage(buffer[:n])
	if err != nil {
		return err
	}
	for _, message := range messages {
		if message.Header.Seq != 1 {
			continue
		}
		if message.Header.Type == unix.NLMSG_ERROR && len(message.Data) >= 4 {
			errno := int32(binary.NativeEndian.Uint32(message.Data[:4]))
			if errno < 0 {
				return syscall.Errno(-errno)
			}
		}
		if message.Header.Type != unix.RTM_NEWROUTE || len(message.Data) < 12 {
			continue
		}
		if message.Data[7] != unix.RTN_UNICAST {
			return fmt.Errorf("peer route is not unicast")
		}
		attributes, err := syscall.ParseNetlinkRouteAttr(&message)
		if err != nil {
			return err
		}
		for _, attribute := range attributes {
			if attribute.Attr.Type == unix.RTA_OIF && len(attribute.Value) >= 4 {
				if int(binary.NativeEndian.Uint32(attribute.Value[:4])) != index {
					return fmt.Errorf("peer route uses another interface; direct fallback refused")
				}
				return nil
			}
		}
	}
	return fmt.Errorf("kernel returned no matching output interface")
}
