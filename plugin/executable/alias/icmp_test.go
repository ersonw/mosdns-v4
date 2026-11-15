package alias

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
)

func buildIPv4Packet(proto byte, src, dst netip.Addr, payload []byte) []byte {
	ihl := 20
	total := ihl + len(payload)
	pkt := make([]byte, total)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(total))
	pkt[8] = 64
	pkt[9] = proto
	copy(pkt[12:16], src.AsSlice())
	copy(pkt[16:20], dst.AsSlice())
	copy(pkt[20:], payload)
	binary.BigEndian.PutUint16(pkt[10:12], onesComplementSum(pkt[:ihl]))
	return pkt
}

func buildEchoRequest(src, dst netip.Addr, id, seq uint16, payload string) []byte {
	icmp := make([]byte, 8+len(payload))
	icmp[0] = icmpEchoReq
	copy(icmp[4:6], []byte{byte(id >> 8), byte(id)})
	copy(icmp[6:8], []byte{byte(seq >> 8), byte(seq)})
	copy(icmp[8:], payload)
	binary.BigEndian.PutUint16(icmp[2:4], onesComplementSum(icmp))
	return buildIPv4Packet(ipProtoICMP, src, dst, icmp)
}

func newICMPTestPlugin(t *testing.T) (*plugin, netip.Addr) {
	t.Helper()
	prefix := netip.MustParsePrefix("192.16.0.0/16")
	a, err := newAllocator(prefix)
	if err != nil {
		t.Fatal(err)
	}
	virtual, err := a.Allocate("6.ipchaxun.net")
	if err != nil {
		t.Fatal(err)
	}
	return &plugin{alloc: a, prefix: prefix, suffix: ".local"}, virtual
}

func TestICMPEchoAnsweredForMappedAddress(t *testing.T) {
	p, virtual := newICMPTestPlugin(t)
	client := netip.MustParseAddr("10.9.0.5")
	req := buildEchoRequest(client, virtual, 0x1234, 7, "ping-payload")

	handled, reply := p.icmpEchoReply(req)
	if !handled {
		t.Fatal("echo request to a mapped address was not handled")
	}
	if len(reply) != len(req) {
		t.Fatalf("reply length = %d, want %d", len(reply), len(req))
	}
	if reply[9] != ipProtoICMP || reply[20] != icmpEchoReply || reply[21] != 0 {
		t.Fatalf("reply type = proto %d icmp %d/%d", reply[9], reply[20], reply[21])
	}
	if got := netip.AddrFrom4([4]byte{reply[12], reply[13], reply[14], reply[15]}); got != virtual {
		t.Fatalf("reply source = %v, want %v", got, virtual)
	}
	if got := netip.AddrFrom4([4]byte{reply[16], reply[17], reply[18], reply[19]}); got != client {
		t.Fatalf("reply destination = %v, want %v", got, client)
	}
	if got := binary.BigEndian.Uint16(reply[24:26]); got != 0x1234 {
		t.Fatalf("id = %#x", got)
	}
	if got := binary.BigEndian.Uint16(reply[26:28]); got != 7 {
		t.Fatalf("seq = %d", got)
	}
	if !bytes.Equal(reply[28:], req[28:]) {
		t.Fatalf("payload changed: %q", reply[28:])
	}
	if sum := onesComplementSum(reply[:20]); sum != 0 {
		t.Fatalf("ip header checksum invalid: %#x", sum)
	}
	if sum := onesComplementSum(reply[20:]); sum != 0 {
		t.Fatalf("icmp checksum invalid: %#x", sum)
	}
}

func TestICMPUnmappedAddressIgnored(t *testing.T) {
	p, _ := newICMPTestPlugin(t)
	free := netip.MustParseAddr("192.16.0.200")
	req := buildEchoRequest(netip.MustParseAddr("10.9.0.5"), free, 1, 1, "x")
	if handled, _ := p.icmpEchoReply(req); handled {
		t.Fatal("echo to an unmapped address was answered")
	}
}

func TestICMPNonEchoAndNonICMPIgnored(t *testing.T) {
	p, virtual := newICMPTestPlugin(t)

	tcp := buildIPv4Packet(6, netip.MustParseAddr("10.9.0.5"), virtual, []byte{0, 0, 0, 0})
	if handled, _ := p.icmpEchoReply(tcp); handled {
		t.Fatal("TCP packet was handled as ICMP")
	}

	// ICMP destination unreachable is not an echo and must not be answered.
	icmp := make([]byte, 8)
	icmp[0] = 3
	icmp[1] = 3
	binary.BigEndian.PutUint16(icmp[2:4], onesComplementSum(icmp))
	other := buildIPv4Packet(ipProtoICMP, netip.MustParseAddr("10.9.0.5"), virtual, icmp)
	if handled, _ := p.icmpEchoReply(other); handled {
		t.Fatal("non-echo ICMP was answered")
	}

	if handled, _ := p.icmpEchoReply([]byte{0x45}); handled {
		t.Fatal("short packet was handled")
	}
}
