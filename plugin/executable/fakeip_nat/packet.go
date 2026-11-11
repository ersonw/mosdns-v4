package fakeipnat

// This file is the packet layer of the tun data path: it parses an IPv4 packet
// read from the tun device, rewrites the addresses/ports and repairs the
// checksums, so a packet addressed to a fake ip can leave towards the real ip
// and come back. It is pure byte manipulation and therefore testable off Linux.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
)

const (
	protoTCP  = 6
	protoUDP  = 17
	protoICMP = 1

	ipv4HeaderMinLen = 20
	tcpMinHeaderLen  = 20
	udpHeaderLen     = 8

	// icmpHeaderLen is the fixed part of every ICMP message.
	icmpHeaderLen = 8
	// icmpTimeExceeded is ICMP type 11; code 0 means "TTL expired in transit".
	icmpTimeExceeded = 11
	// icmpDstUnreachable is ICMP type 3; code 3 means "port unreachable",
	// which is what a host answers for a UDP port nobody listens on.
	icmpDstUnreachable  = 3
	icmpPortUnreachable = 3
	// icmpNetUnreachable / icmpHostUnreachable are the other two codes a host
	// reports when the outlet itself cannot reach the destination.
	icmpNetUnreachable  = 0
	icmpHostUnreachable = 1
	// ttlQuoteLen is how much of the offending payload RFC 792 quotes back.
	ttlQuoteLen = 8
	// ttlReplyTTL is the TTL of the packets the plugin itself originates.
	ttlReplyTTL = 64

	// ipv4 flags: bit 13 is MF, the low 13 bits are the fragment offset.
	ipv4FragMask = 0x3fff
)

var (
	errNotIPv4          = errors.New("not an ipv4 packet")
	errFragment         = errors.New("fragmented ipv4 packets are not supported")
	errUnsupportedProto = errors.New("only tcp and udp are supported")
)

// packetView is a parsed IPv4 packet; the address and port setters rewrite it
// in place, so the caller owns the buffer.
type packetView struct {
	buf      []byte
	ihl      int
	totalLen int
	proto    uint8
	src      netip.Addr
	dst      netip.Addr
	srcPort  uint16
	dstPort  uint16
}

func parseIPv4Packet(buf []byte) (*packetView, error) {
	if len(buf) < ipv4HeaderMinLen || buf[0]>>4 != 4 {
		return nil, errNotIPv4
	}
	ihl := int(buf[0]&0x0f) * 4
	if ihl < ipv4HeaderMinLen || len(buf) < ihl {
		return nil, errNotIPv4
	}
	// Fragment offset or MF set: the transport header may be missing, so the
	// packet cannot be rewritten safely.
	if binary.BigEndian.Uint16(buf[6:8])&ipv4FragMask != 0 {
		return nil, errFragment
	}
	total := int(binary.BigEndian.Uint16(buf[2:4]))
	if total < ihl || total > len(buf) {
		return nil, errNotIPv4
	}

	proto := buf[9]
	minTransport := tcpMinHeaderLen
	if proto == protoUDP {
		minTransport = udpHeaderLen
	}
	if proto != protoTCP && proto != protoUDP {
		return nil, errUnsupportedProto
	}
	if total < ihl+minTransport {
		return nil, errUnsupportedProto
	}

	v := &packetView{buf: buf, ihl: ihl, totalLen: total, proto: proto}
	v.src = netip.AddrFrom4([4]byte{buf[12], buf[13], buf[14], buf[15]})
	v.dst = netip.AddrFrom4([4]byte{buf[16], buf[17], buf[18], buf[19]})
	v.srcPort = binary.BigEndian.Uint16(buf[ihl : ihl+2])
	v.dstPort = binary.BigEndian.Uint16(buf[ihl+2 : ihl+4])
	return v, nil
}

func (v *packetView) setSrc(ip netip.Addr) {
	a := ip.As4()
	copy(v.buf[12:16], a[:])
	v.src = ip
}

func (v *packetView) setDst(ip netip.Addr) {
	a := ip.As4()
	copy(v.buf[16:20], a[:])
	v.dst = ip
}

func (v *packetView) setSrcPort(port uint16) {
	binary.BigEndian.PutUint16(v.buf[v.ihl:], port)
	v.srcPort = port
}

func (v *packetView) setDstPort(port uint16) {
	binary.BigEndian.PutUint16(v.buf[v.ihl+2:], port)
	v.dstPort = port
}

// recomputeChecksums repairs the IPv4 header checksum and the transport checksum
// after the addresses or ports changed.
func (v *packetView) recomputeChecksums() {
	v.recomputeHeaderChecksum()
	v.recomputeTransportChecksum()
}

func (v *packetView) recomputeHeaderChecksum() {
	h := v.buf[:v.ihl]
	h[10], h[11] = 0, 0
	binary.BigEndian.PutUint16(h[10:], ^fold16(sumBytes(h, 0)))
}

func (v *packetView) recomputeTransportChecksum() {
	seg := v.buf[v.ihl:v.totalLen]
	off := 16 // TCP checksum offset
	if v.proto == protoUDP {
		off = 6
	}
	old := binary.BigEndian.Uint16(seg[off:])
	if v.proto == protoUDP && old == 0 {
		// UDP checksum is optional on IPv4 and this sender skipped it.
		return
	}
	binary.BigEndian.PutUint16(seg[off:], 0)

	pseudo := make([]byte, 12)
	s := v.src.As4()
	d := v.dst.As4()
	copy(pseudo[0:4], s[:])
	copy(pseudo[4:8], d[:])
	pseudo[9] = v.proto
	binary.BigEndian.PutUint16(pseudo[10:], uint16(len(seg)))

	sum := sumBytes(seg, sumBytes(pseudo, 0))
	cs := ^fold16(sum)
	if v.proto == protoUDP && cs == 0 {
		// 0 means "no checksum" for UDP, use the equivalent all-ones instead.
		cs = 0xffff
	}
	binary.BigEndian.PutUint16(seg[off:], cs)
}

func sumBytes(b []byte, init uint32) uint32 {
	sum := init
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	return sum
}

func fold16(sum uint32) uint16 {
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return uint16(sum)
}

// checkIPv4Checksum reports whether the header checksum is valid, used by tests
// and by the packet loop to drop corrupted input.
func checkIPv4Checksum(buf []byte) bool {
	if len(buf) < ipv4HeaderMinLen || buf[0]>>4 != 4 {
		return false
	}
	ihl := int(buf[0]&0x0f) * 4
	if ihl < ipv4HeaderMinLen || len(buf) < ihl {
		return false
	}
	return fold16(sumBytes(buf[:ihl], 0)) == 0xffff
}

// checkTransportChecksum reports whether the tcp/udp checksum is valid.
func checkTransportChecksum(v *packetView) bool {
	seg := v.buf[v.ihl:v.totalLen]
	off := 16
	if v.proto == protoUDP {
		off = 6
		if binary.BigEndian.Uint16(seg[off:]) == 0 {
			return true
		}
	}
	pseudo := make([]byte, 12)
	s := v.src.As4()
	d := v.dst.As4()
	copy(pseudo[0:4], s[:])
	copy(pseudo[4:8], d[:])
	pseudo[9] = v.proto
	binary.BigEndian.PutUint16(pseudo[10:], uint16(len(seg)))
	return fold16(sumBytes(seg, sumBytes(pseudo, 0))) == 0xffff
}

// describe is a compact log/diagnostic form of the packet.
func (v *packetView) describe() string {
	return fmt.Sprintf("%s:%d -> %s:%d proto=%d", v.src, v.srcPort, v.dst, v.dstPort, v.proto)
}

// describePacket formats one packet for debug logs. TCP and UDP get the full
// five-tuple; anything else (ICMP, for instance) is described from the IPv4
// header alone, so a perfectly valid echo reply does not show up as a parse
// error.
func describePacket(buf []byte) (string, error) {
	if v, err := parseIPv4Packet(buf); err == nil {
		return v.describe(), nil
	}
	if len(buf) < ipv4HeaderMinLen || buf[0]>>4 != 4 {
		return "", errNotIPv4
	}
	ihl := int(buf[0]&0x0f) * 4
	if ihl < ipv4HeaderMinLen || len(buf) < ihl {
		return "", errNotIPv4
	}
	src := netip.AddrFrom4([4]byte{buf[12], buf[13], buf[14], buf[15]})
	dst := netip.AddrFrom4([4]byte{buf[16], buf[17], buf[18], buf[19]})
	return fmt.Sprintf("%s -> %s proto=%d", src, dst, buf[9]), nil
}

// buildICMPTimeExceeded is the reply a router sends for a packet whose TTL ran
// out: ICMP type 11 code 0 (RFC 792).
func buildICMPTimeExceeded(local, dst netip.Addr, orig []byte) []byte {
	return buildICMPError(local, dst, orig, icmpTimeExceeded, 0)
}

// buildICMPPortUnreachable is what a host answers when a UDP port nobody
// listens on is probed; traceroute needs it to see the device as its destination.
func buildICMPPortUnreachable(local, dst netip.Addr, orig []byte) []byte {
	return buildICMPError(local, dst, orig, icmpDstUnreachable, icmpPortUnreachable)
}

// buildICMPError assembles an ICMP error message quoting the original IPv4
// header plus the first 8 bytes of its payload, with addresses swapped.
func buildICMPError(local, dst netip.Addr, orig []byte, typ, code uint8) []byte {
	ihl := int(orig[0]&0x0f) * 4
	if ihl < ipv4HeaderMinLen || len(orig) < ihl {
		return nil
	}
	// RFC 792 requires the IP header plus the first 8 bytes of the transport
	// header. A shorter quote makes the receiving kernel reject the message
	// as a bad length, so refuse to build one.
	if len(orig) < ihl+ttlQuoteLen {
		return nil
	}
	quote := orig[:ihl+ttlQuoteLen]

	icmpLen := icmpHeaderLen + len(quote)
	total := ipv4HeaderMinLen + icmpLen
	pkt := make([]byte, total)

	// IPv4 header: full TTL, ICMP protocol, addresses swapped.
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(total))
	pkt[8] = ttlReplyTTL
	pkt[9] = protoICMP
	l4 := local.As4()
	s4 := dst.As4()
	copy(pkt[12:16], l4[:])
	copy(pkt[16:20], s4[:])
	binary.BigEndian.PutUint16(pkt[10:12], ^fold16(sumBytes(pkt[:ipv4HeaderMinLen], 0)))

	// ICMP header: type, code, four zero bytes, then the quoted packet.
	icmp := pkt[ipv4HeaderMinLen:]
	icmp[0] = typ
	icmp[1] = code
	copy(icmp[icmpHeaderLen:], quote)
	binary.BigEndian.PutUint16(icmp[2:4], ^fold16(sumBytes(icmp, 0)))
	return pkt
}
