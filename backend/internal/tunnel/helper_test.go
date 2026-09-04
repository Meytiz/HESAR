package tunnel

import (
	"strings"
	"testing"
)

func TestParsePortsBasic(t *testing.T) {
	ports, err := ParsePorts("80, 443,8080")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ports) != 3 || ports[0] != 80 || ports[1] != 443 || ports[2] != 8080 {
		t.Fatalf("unexpected parse result: %v", ports)
	}
}

func TestParsePortsRangeAndDedupe(t *testing.T) {
	ports, err := ParsePorts("8000-8002,8001,9000")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []int{8000, 8001, 8002, 9000}
	if len(ports) != len(want) {
		t.Fatalf("expected %v, got %v", want, ports)
	}
	for i := range want {
		if ports[i] != want[i] {
			t.Fatalf("expected %v, got %v", want, ports)
		}
	}
}

func TestParsePortsRejectsInvalid(t *testing.T) {
	cases := []string{
		"",
		"   ",
		"0",
		"65536",
		"-5",
		"100-50",
		"abc",
		"1-2-3",
	}
	for _, c := range cases {
		if _, err := ParsePorts(c); err == nil {
			t.Fatalf("expected error for %q, got nil", c)
		}
	}
}

func TestParsePortsEnforcesPerTunnelCap(t *testing.T) {
	// 65 ports > MaxPortsPerTunnel (64) → must be rejected so a config
	// like "1-65535" can never exhaust file descriptors.
	_, err := ParsePorts("10000-10064")
	if err == nil || !strings.Contains(err.Error(), "too many ports") {
		t.Fatalf("expected per-tunnel port cap error, got: %v", err)
	}

	// Exactly at the cap must still be accepted.
	ports, err := ParsePorts("10000-10063")
	if err != nil {
		t.Fatalf("cap-boundary range must be accepted: %v", err)
	}
	if len(ports) != MaxPortsPerTunnel {
		t.Fatalf("expected %d ports, got %d", MaxPortsPerTunnel, len(ports))
	}
}
