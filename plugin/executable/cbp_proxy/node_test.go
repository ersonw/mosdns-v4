package cbp_proxy

import (
	"strings"
	"testing"

	"github.com/ersonw/mosdns-v4/pkg/cbpcoord"
)

func TestNodeControlAddressesPreferPublicTCP(t *testing.T) {
	node := cbpcoord.Node{
		ID:                "edge-sg-1",
		PublicAddr:        "203.0.113.10",
		Endpoint:          "quic://203.0.113.10:8443",
		TCPEndpoint:       "tls://203.0.113.10:8443",
		PublicTCPEndpoint: "203.0.113.11:8443",
		LANTCPEndpoint:    "10.0.0.10:8443",
	}
	got := nodeControlAddresses(node)
	if len(got) == 0 {
		t.Fatal("no addresses")
	}
	if got[0] != "203.0.113.11:8443" {
		t.Fatalf("first = %q, all = %+v", got[0], got)
	}
	for _, address := range got {
		if strings.Contains(address, "://") {
			t.Fatalf("scheme survived: %q", address)
		}
	}
	if got[len(got)-1] != "10.0.0.10:8443" {
		t.Fatalf("LAN should be last, got %+v", got)
	}
}

func TestNodeControlAddressesUsePublicAddrPlusTCPPort(t *testing.T) {
	node := cbpcoord.Node{
		ID:          "edge-sg-1",
		PublicAddr:  "203.0.113.10",
		TCPEndpoint: "tls://0.0.0.0:8443",
	}
	got := nodeControlAddresses(node)
	if len(got) != 1 || got[0] != "203.0.113.10:8443" {
		t.Fatalf("addresses = %+v", got)
	}
}

func TestNodeControlAddressesEmptyWhenOnlyQUIC(t *testing.T) {
	node := cbpcoord.Node{
		ID:       "edge-sg-1",
		Endpoint: "quic://203.0.113.10:8443",
	}
	if got := nodeControlAddresses(node); len(got) != 0 {
		t.Fatalf("QUIC endpoint must not become a TCP control address: %+v", got)
	}
}

func TestNodeControlAddressesExpandPublicIPList(t *testing.T) {
	node := cbpcoord.Node{
		ID:                "edge-sg-1",
		PublicTCPEndpoint: "203.0.113.10:8443",
		PublicIPs:         []string{"198.51.100.7", "198.51.100.8:9443", "0.0.0.0"},
		TCPEndpoint:       "tls://10.0.0.10:8443",
	}
	got := nodeControlAddresses(node)
	want := map[string]bool{
		"203.0.113.10:8443": true,
		"198.51.100.7:8443": true,
		"198.51.100.8:9443": true,
		"10.0.0.10:8443":    true,
	}
	for _, address := range got {
		delete(want, address)
	}
	if len(want) != 0 {
		t.Fatalf("missing addresses %v in %+v", want, got)
	}
	for _, address := range got {
		if strings.HasPrefix(address, "0.0.0.0") {
			t.Fatalf("wildcard address survived: %+v", got)
		}
	}
}
