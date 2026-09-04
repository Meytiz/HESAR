package tester

import (
	"strings"
	"testing"
)

// The SSRF guard is the whole point of the vNext tester rewrite: the panel
// is authenticated, but it must not be usable as an internal port scanner.
func TestSSRFGuardBlocksSensitiveTargets(t *testing.T) {
	cases := []struct {
		ip   string
		hint string
	}{
		{"127.0.0.1", "loopback"},
		{"::1", "loopback"},
		{"10.0.0.1", "private"},
		{"172.16.5.5", "private"},
		{"192.168.1.1", "private"},
		{"169.254.169.254", "link-local"}, // cloud metadata endpoint
		{"0.0.0.0", "not a unicast"},
		{"224.0.0.1", "not a unicast"},
	}
	for _, c := range cases {
		res := RunTCPTest(c.ip, 80)
		if res.Success {
			t.Fatalf("%s: probe must not succeed against a blocked target", c.ip)
		}
		if !strings.Contains(res.Details, "blocked") && !strings.Contains(res.Details, "not a unicast") {
			t.Fatalf("%s: expected SSRF guard rejection (hint %q), got: %s", c.ip, c.hint, res.Details)
		}
	}
}

func TestProbeInputValidation(t *testing.T) {
	if res := RunTCPTest("8.8.8.8", 0); res.Success || !strings.Contains(res.Details, "invalid port") {
		t.Fatalf("port 0 must be rejected, got: %+v", res)
	}
	if res := RunTCPTest("8.8.8.8", 70000); res.Success || !strings.Contains(res.Details, "invalid port") {
		t.Fatalf("port 70000 must be rejected, got: %+v", res)
	}
	if res := RunTCPTest("not-an-ip", 80); res.Success || !strings.Contains(res.Details, "invalid target IP") {
		t.Fatalf("garbage IP must be rejected, got: %+v", res)
	}
}

func TestTLSProbeInputValidation(t *testing.T) {
	if res := RunTLSTest("169.254.169.254", 443, "example.com"); res.Success {
		t.Fatalf("TLS probe must honour the SSRF guard: %+v", res)
	}
}

func TestQUICProbeInputValidation(t *testing.T) {
	if res := RunQUICTest("10.1.2.3", 443); res.Success {
		t.Fatalf("QUIC probe must honour the SSRF guard: %+v", res)
	}
}
