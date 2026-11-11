package fakeipnat

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"
)

func TestForwardPacketRewritesToRealIP(t *testing.T) {
	p := newTestPlugin(t, "198.18.0.0/16")
	ctx := context.Background()

	realIPs := []string{"1.2.3.4"}
	fakeIP, err := p.recordAndAllocate(ctx, "example.com", realIPs)
	if err != nil {
		t.Fatalf("recordAndAllocate: %v", err)
	}

	buf := buildTCPPacket(t, "10.0.0.2", fakeIP, 5000, 443)
	v, err := parseIPv4Packet(buf)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	gotReal, err := p.forwardPacket(ctx, v)
	if err != nil {
		t.Fatalf("forwardPacket: %v", err)
	}
	if gotReal.String() != "1.2.3.4" {
		t.Fatalf("real ip = %s, want 1.2.3.4", gotReal)
	}
	if v.src.String() != fakeIP {
		t.Fatalf("source = %s, want the fake ip %s", v.src, fakeIP)
	}
	if v.dst.String() != "1.2.3.4" {
		t.Fatalf("destination = %s, want 1.2.3.4", v.dst)
	}
}

func TestReversePacketMapsReplyBackToClient(t *testing.T) {
	p := newTestPlugin(t, "198.18.0.0/16")
	ctx := context.Background()

	fakeIP, err := p.recordAndAllocate(ctx, "example.com", []string{"1.2.3.4"})
	if err != nil {
		t.Fatalf("recordAndAllocate: %v", err)
	}

	client := buildTCPPacket(t, "10.0.0.2", fakeIP, 5000, 443)
	v, err := parseIPv4Packet(client)
	if err != nil {
		t.Fatalf("parse client packet: %v", err)
	}
	if _, err := p.forwardPacket(ctx, v); err != nil {
		t.Fatalf("forwardPacket: %v", err)
	}
	natPort := v.srcPort
	if natPort < natPortMin {
		t.Fatalf("translated source port = %d, want an ephemeral port", natPort)
	}

	// The reply arrives from the real ip towards the fake ip on the port the
	// plugin picked.
	reply := buildTCPPacket(t, "1.2.3.4", fakeIP, 443, natPort)
	rp, err := parseIPv4Packet(reply)
	if err != nil {
		t.Fatalf("parse reply: %v", err)
	}
	ok, err := p.reversePacket(rp)
	if err != nil {
		t.Fatalf("reversePacket: %v", err)
	}
	if !ok {
		t.Fatal("reply was not recognised as part of the flow")
	}
	if rp.src.String() != fakeIP {
		t.Fatalf("reply source = %s, want the fake ip %s", rp.src, fakeIP)
	}
	if rp.dst.String() != "10.0.0.2" || rp.dstPort != 5000 {
		t.Fatalf("reply destination = %s:%d, want 10.0.0.2:5000", rp.dst, rp.dstPort)
	}
}

func TestConntrackReusesPortForSameFlow(t *testing.T) {
	p := newTestPlugin(t, "198.18.0.0/16")
	ctx := context.Background()

	fakeIP, err := p.recordAndAllocate(ctx, "example.com", []string{"1.2.3.4"})
	if err != nil {
		t.Fatalf("recordAndAllocate: %v", err)
	}

	first, _ := parseIPv4Packet(buildTCPPacket(t, "10.0.0.2", fakeIP, 5000, 443))
	if _, err := p.forwardPacket(ctx, first); err != nil {
		t.Fatalf("first forward: %v", err)
	}
	second, _ := parseIPv4Packet(buildTCPPacket(t, "10.0.0.2", fakeIP, 5000, 443))
	if _, err := p.forwardPacket(ctx, second); err != nil {
		t.Fatalf("second forward: %v", err)
	}
	if first.srcPort != second.srcPort {
		t.Fatalf("same flow got different ports: %d vs %d", first.srcPort, second.srcPort)
	}

	// A different client port is a different flow and must get its own port.
	third, _ := parseIPv4Packet(buildTCPPacket(t, "10.0.0.2", fakeIP, 5001, 443))
	if _, err := p.forwardPacket(ctx, third); err != nil {
		t.Fatalf("third forward: %v", err)
	}
	if third.srcPort == first.srcPort {
		t.Fatalf("distinct flows share the port %d", first.srcPort)
	}
}

func TestConntrackExpiresIdleFlows(t *testing.T) {
	c := newConntrack(16, 10*time.Millisecond)
	key := forwardKey{
		proto:      protoTCP,
		fake:       netip.MustParseAddr("198.18.0.2"),
		client:     netip.MustParseAddr("10.0.0.2"),
		clientPort: 5000,
		serverPort: 443,
	}
	if _, err := c.forward(key, netip.MustParseAddr("1.2.3.4")); err != nil {
		t.Fatalf("forward: %v", err)
	}
	if c.len() != 1 {
		t.Fatalf("conntrack size = %d, want 1", c.len())
	}

	c.expire(20 * time.Millisecond)
	if c.len() != 0 {
		t.Fatalf("idle flow was not expired, size = %d", c.len())
	}
}

func TestForwardPacketRejectsUnknownFakeIP(t *testing.T) {
	p := newTestPlugin(t, "198.18.0.0/16")
	v, err := parseIPv4Packet(buildTCPPacket(t, "10.0.0.2", "198.18.0.9", 5000, 443))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, err := p.forwardPacket(context.Background(), v); !errors.Is(err, errNoFakeIPMapping) {
		t.Fatalf("forwardPacket = %v, want errNoFakeIPMapping", err)
	}
}

func TestForwardPacketRejectsOutsideRange(t *testing.T) {
	p := newTestPlugin(t, "198.18.0.0/16")
	v, err := parseIPv4Packet(buildTCPPacket(t, "10.0.0.2", "8.8.8.8", 5000, 53))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, err := p.forwardPacket(context.Background(), v); err == nil {
		t.Fatal("a destination outside ipv4_range should be rejected")
	}
}
