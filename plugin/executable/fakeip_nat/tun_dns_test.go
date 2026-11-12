package fakeipnat

import (
	"context"
	"net/netip"
	"testing"
)

// TestDNSPacketSpotsQueries keeps the one destination class the device accepts
// apart from ordinary traffic: UDP and TCP to port 53, nothing else.
func TestDNSPacketSpotsQueries(t *testing.T) {
	q := buildUDPPacket(t, "10.0.0.9", "8.8.8.8", 40000, 53, []byte("query"))

	if !dnsPacket(q) {
		t.Fatal("a DNS query was not recognised")
	}
	if dnsPacket(buildUDPPacket(t, "10.0.0.9", "8.8.8.8", 40000, 443, []byte("tls"))) {
		t.Fatal("a non-DNS datagram was accepted as DNS")
	}
	if !dnsFlow(53) {
		t.Fatal("port 53 was not recognised as DNS")
	}
	if dnsFlow(80) || dnsFlow(443) {
		t.Fatal("a non-DNS port was treated as DNS")
	}
}

// TestOwnsTunDestinationAcceptsDNS pins the deliberate widening: DNS is carried
// through the device while every other foreign destination stays dropped.
func TestOwnsTunDestinationAcceptsDNS(t *testing.T) {
	p := newNativePlugin(t, &fakeRunner{}, func(context.Context, string) bool { return true })

	if !p.ownsTunDestination(buildUDPPacket(t, "10.0.0.9", "8.8.8.8", 40000, 53, []byte("query"))) {
		t.Fatal("DNS to a public resolver was dropped")
	}
	if p.ownsTunDestination(buildUDPPacket(t, "10.0.0.9", "8.8.8.8", 40000, 443, []byte("tls"))) {
		t.Fatal("a non-DNS flow to a foreign address was accepted")
	}
}

// TestPrecheckKeepsDNSOnTheDeviceAddress: the device answers UDP with ICMP port
// unreachable because it runs no services, except on port 53, where the DNS
// relay answers instead.
func TestPrecheckKeepsDNSOnTheDeviceAddress(t *testing.T) {
	st := &tunStack{local: netip.MustParseAddr("198.18.0.1")}

	reply, drop := st.precheck(buildUDPPacket(t, "10.0.0.9", "198.18.0.1", 40000, 9999, []byte("probe")))
	if !drop || reply == nil {
		t.Fatalf("a probe of the device address was not refused: drop=%v reply=%v", drop, len(reply))
	}

	reply, drop = st.precheck(buildUDPPacket(t, "10.0.0.9", "198.18.0.1", 40000, 53, []byte("query")))
	if drop || reply != nil {
		t.Fatalf("a DNS query was refused instead of being relayed: drop=%v reply=%v", drop, len(reply))
	}
}
