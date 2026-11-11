package fakeipnat

// Both traceroute sides must see the same thing: every hop, including the tun
// device itself, is shown as a stand-in address of ipv4_range whose reverse
// lookup names the real address with the configured suffix.

import (
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
)

// The device's own address is a local address of the client, so a reply coming
// from it is dropped as a martian source. Answering under a stand-in keeps the
// first hop visible.
func TestPrecheckAnswersFirstHopAsVirtualAddress(t *testing.T) {
	local := netip.MustParseAddr("198.18.0.1")
	st, err := newTunStack(defaultTunMTU, local)
	if err != nil {
		t.Fatalf("newTunStack: %v", err)
	}
	defer st.close()

	stand := netip.MustParseAddr("198.19.240.7")
	st.virtualSrc = func(netip.Addr) (netip.Addr, bool) { return stand, true }

	client := netip.MustParseAddr("192.168.10.20")
	pkt := buildUDPPacket(t, client.String(), "198.18.0.200", 40000, 33434, []byte("abcdefgh"))
	pkt[8] = 1

	reply, drop := st.precheck(pkt)
	if !drop || reply == nil {
		t.Fatalf("ttl 1 must be answered, got drop=%v len=%d", drop, len(reply))
	}
	gotSrc := netip.AddrFrom4([4]byte{reply[12], reply[13], reply[14], reply[15]})
	gotDst := netip.AddrFrom4([4]byte{reply[16], reply[17], reply[18], reply[19]})
	if gotSrc != stand {
		t.Fatalf("reply source = %s, want the stand-in %s", gotSrc, stand)
	}
	if gotDst != client {
		t.Fatalf("reply destination = %s, want %s", gotDst, client)
	}
	if reply[20] != icmpTimeExceeded {
		t.Fatalf("icmp type = %d, want time exceeded", reply[20])
	}
	if !checkIPv4Checksum(reply) || fold16(sumBytes(reply[ipv4HeaderMinLen:], 0)) != 0xffff {
		t.Fatal("reply checksums are wrong")
	}
}

// Without the hook (unit tests, non-tun code paths) the device still answers as
// itself, so nothing silently changes for existing callers.
func TestPrecheckKeepsDeviceAddressWithoutHook(t *testing.T) {
	local := netip.MustParseAddr("198.18.0.1")
	st, err := newTunStack(defaultTunMTU, local)
	if err != nil {
		t.Fatalf("newTunStack: %v", err)
	}
	defer st.close()

	pkt := buildUDPPacket(t, "192.168.10.20", "198.18.0.200", 40000, 33434, []byte("abcdefgh"))
	pkt[8] = 1
	reply, drop := st.precheck(pkt)
	if !drop || reply == nil {
		t.Fatalf("ttl 1 must be answered, got drop=%v len=%d", drop, len(reply))
	}
	gotSrc := netip.AddrFrom4([4]byte{reply[12], reply[13], reply[14], reply[15]})
	if gotSrc != local {
		t.Fatalf("reply source = %s, want %s", gotSrc, local)
	}
}

func TestHopSourceVirtualizesTimeExceededOnly(t *testing.T) {
	p := newTestPlugin(t, "198.18.0.0/16")
	hop := netip.MustParseAddr("11.10.12.1")

	virtual := p.hopSource(hop, icmpTimeExceeded)
	if virtual == hop || !p.prefix.Contains(virtual) {
		t.Fatalf("hop shown as %s, want an address of the range", virtual)
	}
	if real, ok := p.hopOf(virtual); !ok || real != hop {
		t.Fatalf("reverse lookup of %s = %s/%v, want %s", virtual, real, ok, hop)
	}
	// A destination unreachable names the endpoint the client asked for.
	if got := p.hopSource(hop, icmpDstUnreachable); got != hop {
		t.Fatalf("unreachable shown as %s, want the real address %s", got, hop)
	}
	// An address of the range is already virtual: it is not virtualized again.
	if got := p.hopSource(virtual, icmpTimeExceeded); got != virtual {
		t.Fatalf("virtual address shown as %s, want %s", got, virtual)
	}
}

func TestRelayICMPErrorShowsVirtualHop(t *testing.T) {
	p := newTestPlugin(t, "198.18.0.0/16")
	var written []byte
	p.icmpMu.Lock()
	p.icmp = newICMPRelay(func(b []byte) error { written = b; return nil })
	p.icmpMu.Unlock()

	client := netip.MustParseAddr("192.168.10.20")
	fakeIP := netip.MustParseAddr("198.18.0.27")
	flow := icmpFlow{client: client, clientPort: 40000, fakeIP: fakeIP, fakePort: 33434}
	quote := buildClientUDPQuote(flow)
	// The upstream socket port is what the quoted header carries.
	const upstreamPort = 51000
	flow.quote = quote
	p.icmp.add(upstreamPort, flow)

	msg := make([]byte, icmpHeaderLen+len(quote))
	msg[0] = icmpTimeExceeded
	copy(msg[icmpHeaderLen:], quote)
	binary.BigEndian.PutUint16(msg[icmpHeaderLen+ipv4HeaderMinLen:], upstreamPort)

	hop := netip.MustParseAddr("11.10.12.1")
	p.relayICMPError(&net.IPAddr{IP: net.IP(hop.AsSlice())}, msg)

	if written == nil {
		t.Fatal("nothing was written to the client")
	}
	from := netip.AddrFrom4([4]byte{written[12], written[13], written[14], written[15]})
	if !p.prefix.Contains(from) {
		t.Fatalf("error source = %s, want an address of the range", from)
	}
	if real, ok := p.hopOf(from); !ok || real != hop {
		t.Fatalf("reverse lookup of %s = %s/%v, want the hop %s", from, real, ok, hop)
	}
	if got := netip.AddrFrom4([4]byte{written[16], written[17], written[18], written[19]}); got != client {
		t.Fatalf("destination = %s, want the client %s", got, client)
	}
	if written[ipv4HeaderMinLen] != icmpTimeExceeded {
		t.Fatalf("icmp type = %d, want time exceeded", written[ipv4HeaderMinLen])
	}
}

// A port unreachable comes from the destination, so the client must see the
// address it asked for rather than a stand-in.
func TestRelayICMPErrorKeepsDestinationOnPortUnreachable(t *testing.T) {
	p := newTestPlugin(t, "198.18.0.0/16")
	var written []byte
	p.icmpMu.Lock()
	p.icmp = newICMPRelay(func(b []byte) error { written = b; return nil })
	p.icmpMu.Unlock()

	client := netip.MustParseAddr("192.168.10.20")
	fakeIP := netip.MustParseAddr("198.18.0.27")
	flow := icmpFlow{client: client, clientPort: 40000, fakeIP: fakeIP, fakePort: 33434}
	quote := buildClientUDPQuote(flow)
	flow.quote = quote
	const upstreamPort = 51001
	p.icmp.add(upstreamPort, flow)

	msg := make([]byte, icmpHeaderLen+len(quote))
	msg[0] = icmpDstUnreachable
	msg[1] = icmpPortUnreachable
	copy(msg[icmpHeaderLen:], quote)
	binary.BigEndian.PutUint16(msg[icmpHeaderLen+ipv4HeaderMinLen:], upstreamPort)

	// h.opSource keeps the real address for this type, so the written source
	// must be exactly the sender.
	dst, _ := netip.AddrFromSlice(net.IP{93, 184, 216, 34}.To4())
	p.relayICMPError(&net.IPAddr{IP: net.IP(dst.AsSlice())}, msg)

	if written == nil {
		t.Fatal("nothing was written to the client")
	}
	from := netip.AddrFrom4([4]byte{written[12], written[13], written[14], written[15]})
	if from != dst {
		t.Fatalf("error source = %s, want the real target %s", from, dst)
	}
}

// The views must survive long enough for a PTR lookup that follows the probe.
func TestHopViewHoldsTheFirstHop(t *testing.T) {
	p := newTestPlugin(t, "198.18.0.0/16")
	local := p.reservedAddr()
	virtual, ok := p.hopFakeFor(local)
	if !ok {
		t.Fatal("the device address cannot be shown as a hop")
	}
	if virtual == local {
		t.Fatal("the device address was handed back unchanged")
	}
	if !p.prefix.Contains(virtual) {
		t.Fatalf("hop address %s is outside the range", virtual)
	}
	if real, ok := p.hopOf(virtual); !ok || real != local {
		t.Fatalf("reverse lookup of %s = %s/%v, want the device %s", virtual, real, ok, local)
	}
}
