package fakeipnat

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

// buildTCPPacket lays out a minimal TCP/IPv4 packet with valid checksums.
func buildTCPPacket(t *testing.T, src, dst string, srcPort, dstPort uint16) []byte {
	t.Helper()
	s := netip.MustParseAddr(src).As4()
	d := netip.MustParseAddr(dst).As4()

	buf := make([]byte, ipv4HeaderMinLen+tcpMinHeaderLen)
	buf[0] = 0x45
	binary.BigEndian.PutUint16(buf[2:4], uint16(len(buf)))
	buf[8] = 64
	buf[9] = protoTCP
	copy(buf[12:16], s[:])
	copy(buf[16:20], d[:])
	binary.BigEndian.PutUint16(buf[20:22], srcPort)
	binary.BigEndian.PutUint16(buf[22:24], dstPort)
	binary.BigEndian.PutUint32(buf[24:28], 0x11223344) // seq
	buf[32] = 0x50                                     // data offset 5
	buf[33] = 0x02                                     // SYN

	v, err := parseIPv4Packet(buf)
	if err != nil {
		t.Fatalf("build packet: %v", err)
	}
	v.recomputeChecksums()
	if !tcpChecksumOK(t, buf) {
		t.Fatal("built packet has an invalid tcp checksum")
	}
	return buf
}

// tcpChecksumOK recomputes the transport checksum with its own summation so a
// bookkeeping mistake in the implementation is caught.
func tcpChecksumOK(t *testing.T, buf []byte) bool {
	t.Helper()
	ihl := int(buf[0]&0x0f) * 4
	seg := buf[ihl:]
	sum := uint32(0)
	for i := 0; i+1 < len(seg); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(seg[i:]))
	}
	src := netip.AddrFrom4([4]byte{buf[12], buf[13], buf[14], buf[15]})
	dst := netip.AddrFrom4([4]byte{buf[16], buf[17], buf[18], buf[19]})
	a, b := src.As4(), dst.As4()
	for i := 0; i < 4; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(a[i:]))
		sum += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	sum += uint32(buf[9]) // protocol
	sum += uint32(len(seg))

	ipSum := uint32(0)
	hdr := buf[:ihl]
	for i := 0; i+1 < len(hdr); i += 2 {
		ipSum += uint32(binary.BigEndian.Uint16(hdr[i:]))
	}
	return folded16(sum) == 0xffff && folded16(ipSum) == 0xffff
}

func folded16(sum uint32) uint16 {
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return uint16(sum)
}

func TestParseIPv4PacketRejectsBadInput(t *testing.T) {
	good := buildTCPPacket(t, "10.0.0.2", "198.18.0.2", 5000, 443)

	if _, err := parseIPv4Packet([]byte{0x60, 0x00}); err != errNotIPv4 {
		t.Fatalf("ipv6 = %v, want errNotIPv4", err)
	}
	if _, err := parseIPv4Packet(good[:10]); err != errNotIPv4 {
		t.Fatalf("truncated = %v, want errNotIPv4", err)
	}

	frag := append([]byte(nil), good...)
	binary.BigEndian.PutUint16(frag[6:8], 0x2000) // MF
	if _, err := parseIPv4Packet(frag); err != errFragment {
		t.Fatalf("fragment = %v, want errFragment", err)
	}

	icmp := append([]byte(nil), good...)
	icmp[9] = 1
	if _, err := parseIPv4Packet(icmp); err != errUnsupportedProto {
		t.Fatalf("icmp = %v, want errUnsupportedProto", err)
	}
}

func TestPacketRewriteRepairsChecksums(t *testing.T) {
	buf := buildTCPPacket(t, "10.0.0.2", "198.18.0.2", 5000, 443)

	v, err := parseIPv4Packet(buf)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !tcpChecksumOK(t, buf) {
		t.Fatal("packet should start with valid checksums")
	}

	v.setSrc(netip.MustParseAddr("198.18.0.2"))
	v.setDst(netip.MustParseAddr("1.2.3.4"))
	v.setSrcPort(12000)
	v.recomputeChecksums()

	if v.src != netip.MustParseAddr("198.18.0.2") || v.dst != netip.MustParseAddr("1.2.3.4") {
		t.Fatalf("addresses = %s -> %s", v.src, v.dst)
	}
	if v.srcPort != 12000 || v.dstPort != 443 {
		t.Fatalf("ports = %d -> %d", v.srcPort, v.dstPort)
	}
	if !tcpChecksumOK(t, buf) {
		t.Fatal("checksums were not repaired after the rewrite")
	}
}

func TestPacketSettersKeepUDPChecksumValid(t *testing.T) {
	s := netip.MustParseAddr("10.0.0.2").As4()
	d := netip.MustParseAddr("198.18.0.2").As4()
	buf := make([]byte, ipv4HeaderMinLen+udpHeaderLen)
	buf[0] = 0x45
	binary.BigEndian.PutUint16(buf[2:4], uint16(len(buf)))
	buf[8] = 64
	buf[9] = protoUDP
	copy(buf[12:16], s[:])
	copy(buf[16:20], d[:])
	binary.BigEndian.PutUint16(buf[20:22], 5353)
	binary.BigEndian.PutUint16(buf[22:24], 53)
	binary.BigEndian.PutUint16(buf[24:26], uint16(len(buf)-ipv4HeaderMinLen))

	v, err := parseIPv4Packet(buf)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	v.recomputeChecksums()
	v.setDst(netip.MustParseAddr("1.2.3.4"))
	v.recomputeChecksums()

	if !checkIPv4Checksum(buf) {
		t.Fatal("ipv4 checksum invalid")
	}
	if !checkTransportChecksum(v) {
		t.Fatal("udp checksum invalid after the rewrite")
	}
}
