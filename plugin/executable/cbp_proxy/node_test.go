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

func TestNodeControlAddressesPublishedListIsAuthoritative(t *testing.T) {
	node := cbpcoord.Node{
		ID:                "edge-sg-1",
		PublicAddr:        "203.0.113.99",
		PublicTCPEndpoint: "203.0.113.10:8443",
		ControlAddresses:  []string{"198.51.100.7:8443", "198.51.100.8:9443"},
		TCPEndpoint:       "tls://10.0.0.10:8443",
		LANTCPEndpoint:    "tls://10.0.0.11:8443",
	}
	got := nodeControlAddresses(node)
	want := []string{"198.51.100.7:8443", "198.51.100.8:9443"}
	if len(got) != len(want) {
		t.Fatalf("addresses = %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("addresses = %+v, want %+v", got, want)
		}
	}
}

func TestNodeControlAddressesLegacyFallbackSkipsDisplayPublicAddr(t *testing.T) {
	node := cbpcoord.Node{
		ID:                "edge-sg-1",
		PublicAddr:        "203.0.113.99",
		PublicTCPEndpoint: "203.0.113.10:8443",
		TCPEndpoint:       "tls://10.0.0.10:8443",
	}
	got := nodeControlAddresses(node)
	for _, address := range got {
		if address == "203.0.113.99:8443" {
			t.Fatalf("display public_addr must not be dialed: %+v", got)
		}
	}
}
