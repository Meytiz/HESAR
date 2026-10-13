package tester

import (
	"net"
	"testing"
)

func TestProbeRejectsInternalAndReservedTargets(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "::1", "10.10.34.34", "169.254.169.254", "100.64.1.1", "0.0.0.1", "198.18.0.1", "203.0.113.2", "2001:db8::1", "::ffff:127.0.0.1", "64:ff9b::7f00:1"} {
		if err := isDisallowedTarget(net.ParseIP(ip)); err == nil {
			t.Errorf("accepted %s", ip)
		}
	}
	if err := isDisallowedTarget(net.ParseIP("1.1.1.1")); err != nil {
		t.Fatal(err)
	}
}
