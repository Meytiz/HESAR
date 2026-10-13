package config

import "testing"

func TestManagedCarrierValidation(t *testing.T) {
	base := validTunnel()
	base.Carrier = "gre"
	base.CarrierPeerIP = "192.0.2.2"
	base.CarrierLocalInner = "10.77.0.1"
	base.CarrierRemoteInner = "10.77.0.2"
	base.CarrierMTU = 1280
	if err := ValidateTunnel(base); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*TunnelConfig){
		func(c *TunnelConfig) { c.CarrierPeerIP = "255.255.255.255" },
		func(c *TunnelConfig) { c.CarrierPeerIP = "127.0.0.1" },
		func(c *TunnelConfig) { c.ProxyURL = "socks5://127.0.0.1:1080" },
		func(c *TunnelConfig) { c.UnderlayInterface = "hsl3-other" },
		func(c *TunnelConfig) { c.CarrierLocalInner = "1.1.1.1" },
		func(c *TunnelConfig) { c.CarrierRemoteInner = c.CarrierLocalInner },
		func(c *TunnelConfig) { c.Protocol = "quic"; c.CarrierMTU = 1200 },
		func(c *TunnelConfig) { c.Carrier = "paqet"; c.CarrierPort = 19999; c.CarrierAuth = "weak" },
	} {
		c := *base
		mutate(&c)
		if ValidateTunnel(&c) == nil {
			t.Fatalf("accepted invalid managed configuration: %+v", c)
		}
	}
}
