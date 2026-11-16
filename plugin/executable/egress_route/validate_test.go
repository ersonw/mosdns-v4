package egress_route

import "testing"

// A proxy-only exit is the shape a data-plane plugin borrows when it wants
// nothing but "send my flows through this proxy". It owns no mark and no
// table, and rejecting it would push the proxy back into every plugin.
func TestProxyOnlyExitIsValid(t *testing.T) {
	a := &Args{Proxy: "gost://user:pass@10.0.0.1:1080", ProxyInsecure: true}
	if err := a.validate(); err != nil {
		t.Fatalf("a proxy-only exit must validate: %v", err)
	}
}

func TestHalfAnExitIsRejected(t *testing.T) {
	cases := map[string]*Args{
		"proxy with mark but no table": {Proxy: "socks5://10.0.0.1:1080", Mark: 126},
		"proxy with table but no mark": {Proxy: "socks5://10.0.0.1:1080", RouteTable: "126"},
		"routed exit without next hop": {Mark: 126, RouteTable: "126"},
		"routed exit without a table":  {Mark: 126, NextHopDev: "wg0"},
		"no mark at all":               {RouteTable: "126", NextHopDev: "wg0"},
	}
	for name, a := range cases {
		if err := a.validate(); err == nil {
			t.Fatalf("%s must be rejected", name)
		}
	}
}

func TestRoutedExitIsValid(t *testing.T) {
	a := &Args{Mark: 126, RouteTable: "126", NextHop: "11.10.12.1", NextHopDev: "wg0"}
	if err := a.validate(); err != nil {
		t.Fatalf("a complete routed exit must validate: %v", err)
	}
}

// One exit can own a mark and a table while borrowing the proxy link from a
// proxy-only outlet: marks cannot be shared, the link can.
func TestProxyFromIsAccepted(t *testing.T) {
	a := &Args{Mark: 126, RouteTable: "126", NextHop: "11.10.12.1", NextHopDev: "wg0", ProxyFrom: "egress_proxy"}
	if err := a.validate(); err != nil {
		t.Fatalf("a routed exit borrowing its proxy must validate: %v", err)
	}
	if err := (&Args{Proxy: "gost://10.0.0.1:1080", ProxyFrom: "egress_proxy"}).validate(); err == nil {
		t.Fatal("proxy and proxy_from together must be rejected")
	}
}
