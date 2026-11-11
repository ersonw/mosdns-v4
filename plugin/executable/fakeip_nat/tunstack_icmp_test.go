package fakeipnat

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

// The device must answer like a host for traceroute: a packet for a fake IP
// whose TTL ran out comes back as ICMP Time Exceeded quoting the original.
func TestPrecheckBuildsTimeExceeded(t *testing.T) {
	local := netip.MustParseAddr("198.18.0.1")
	st, err := newTunStack(defaultTunMTU, local)
	if err != nil {
		t.Fatalf("newTunStack: %v", err)
	}
	defer st.close()

	client := netip.MustParseAddr("192.168.1.10")
	pkt := buildUDPPacket(t, client.String(), "198.18.0.2", 50000, 33434, []byte("abcdefgh"))
	pkt[8] = 1 // traceroute's first probe

	reply, drop := st.precheck(pkt)
	if !drop || reply == nil {
		t.Fatalf("ttl 1 to a fake ip must be answered, got drop=%v reply len=%d", drop, len(reply))
	}

	if reply[9] != protoICMP {
		t.Fatalf("protocol = %d, want icmp(%d)", reply[9], protoICMP)
	}
	if reply[20] != icmpTimeExceeded || reply[21] != 0 {
		t.Fatalf("icmp type/code = %d/%d, want 11/0", reply[20], reply[21])
	}
	if !checkIPv4Checksum(reply) {
		t.Fatal("ipv4 header checksum is wrong")
	}
	if fold16(sumBytes(reply[ipv4HeaderMinLen:], 0)) != 0xffff {
		t.Fatal("icmp checksum is wrong")
	}

	gotSrc := netip.AddrFrom4([4]byte{reply[12], reply[13], reply[14], reply[15]})
	gotDst := netip.AddrFrom4([4]byte{reply[16], reply[17], reply[18], reply[19]})
	if gotSrc != local || gotDst != client {
		t.Fatalf("reply %s -> %s, want %s -> %s", gotSrc, gotDst, local, client)
	}

	// IPv4 header + ICMP header + quoted IPv4 header + first 8 payload bytes.
	if want := ipv4HeaderMinLen + icmpHeaderLen + ipv4HeaderMinLen + ttlQuoteLen; len(reply) != want {
		t.Fatalf("reply length = %d, want %d", len(reply), want)
	}
	// The quoted 8 bytes start at the transport header: here the UDP source
	// port, which proves the original datagram is being echoed back.
	if got := binary.BigEndian.Uint16(reply[len(reply)-ttlQuoteLen:]); got != 50000 {
		t.Fatalf("quoted source port = %d, want 50000", got)
	}
}

// A UDP probe to the device's own address must be refused like a host with no
// listener: traceroute then reports arrival instead of reaching the allocator.
func TestPrecheckRefusesLocalUDPProbe(t *testing.T) {
	local := netip.MustParseAddr("198.18.0.1")
	st, err := newTunStack(defaultTunMTU, local)
	if err != nil {
		t.Fatalf("newTunStack: %v", err)
	}
	defer st.close()

	pkt := buildUDPPacket(t, "198.18.0.1", local.String(), 47589, 33442, []byte("abcdefgh"))

	reply, drop := st.precheck(pkt)
	if !drop || reply == nil {
		t.Fatalf("local udp probe must be refused, got drop=%v reply len=%d", drop, len(reply))
	}
	if reply[20] != icmpDstUnreachable || reply[21] != icmpPortUnreachable {
		t.Fatalf("icmp type/code = %d/%d, want 3/3", reply[20], reply[21])
	}
	if !checkIPv4Checksum(reply) || fold16(sumBytes(reply[ipv4HeaderMinLen:], 0)) != 0xffff {
		t.Fatal("checksums of the port-unreachable reply are wrong")
	}
}

// Echo requests to the device must reach the stack, which answers them itself.
func TestPrecheckLeavesLocalEchoAlone(t *testing.T) {
	local := netip.MustParseAddr("198.18.0.1")
	st, err := newTunStack(defaultTunMTU, local)
	if err != nil {
		t.Fatalf("newTunStack: %v", err)
	}
	defer st.close()

	pkt := buildEchoPacket(t, "198.18.0.1", local.String(), 0x1234, []byte("ping-payload"))

	if reply, drop := st.precheck(pkt); drop || reply != nil {
		t.Fatalf("local echo must go to the stack, got drop=%v reply len=%d", drop, len(reply))
	}
}

// buildEchoPacket builds a minimal IPv4 + ICMP echo request for precheck tests.
func buildEchoPacket(t *testing.T, src, dst string, id uint16, payload []byte) []byte {
	t.Helper()
	buf := make([]byte, ipv4HeaderMinLen+icmpHeaderLen+len(payload))
	buf[0] = 0x45
	binary.BigEndian.PutUint16(buf[2:4], uint16(len(buf)))
	buf[8] = 64
	buf[9] = protoICMP
	s4 := netip.MustParseAddr(src).As4()
	d4 := netip.MustParseAddr(dst).As4()
	copy(buf[12:16], s4[:])
	copy(buf[16:20], d4[:])
	binary.BigEndian.PutUint16(buf[10:12], ^fold16(sumBytes(buf[:ipv4HeaderMinLen], 0)))
	buf[20] = 8 // echo request
	buf[21] = 0
	binary.BigEndian.PutUint16(buf[24:26], id)
	copy(buf[28:], payload)
	binary.BigEndian.PutUint16(buf[22:24], ^fold16(sumBytes(buf[20:], 0)))
	return buf
}

// An echo reply must be describable for logs instead of being rejected by the
// tcp/udp-only parser.
func TestDescribePacketAcceptsICMP(t *testing.T) {
	pkt := buildEchoPacket(t, "198.18.0.1", "198.18.0.1", 0x1234, []byte("ping-payload"))
	desc, err := describePacket(pkt)
	if err != nil {
		t.Fatalf("describePacket: %v", err)
	}
	if want := "198.18.0.1 -> 198.18.0.1 proto=1"; desc != want {
		t.Fatalf("describePacket = %q, want %q", desc, want)
	}
}
