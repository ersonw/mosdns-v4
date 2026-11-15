package alias

// icmp.go answers ICMP echo for virtual addresses inside the plugin. The
// netstack has no endpoint for a virtual address: it only carries a name, and
// the address is consumed by the plugin's own mapping. Answering here keeps
// `ping <alias host>` working without dialling the real host and without
// exposing the real address.

import (
	"encoding/binary"
	"net/netip"

	"go.uber.org/zap"
)

const (
	ipProtoICMP   = 1
	icmpEchoReply = 0
	icmpEchoReq   = 8
	icmpTTL       = 64
)

// icmpEchoReply inspects one raw IPv4 packet. When it is an echo request to a
// mapped virtual address, it returns handled=true and the reply packet to write
// back to the device; handled=false leaves the packet to the caller.
func (p *plugin) icmpEchoReply(pkt []byte) (bool, []byte) {
	if p == nil || p.alloc == nil {
		return false, nil
	}
	if len(pkt) < 20+8 || pkt[0]>>4 != 4 {
		return false, nil
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < 20 || len(pkt) < ihl+8 {
		return false, nil
	}
	if pkt[9] != ipProtoICMP {
		return false, nil
	}
	total := int(binary.BigEndian.Uint16(pkt[2:4]))
	if total < ihl+8 || total > len(pkt) {
		return false, nil
	}
	// A fragmented packet is not an echo we can answer safely.
	if binary.BigEndian.Uint16(pkt[6:8])&0x1fff != 0 {
		return false, nil
	}

	dst := netip.AddrFrom4([4]byte{pkt[16], pkt[17], pkt[18], pkt[19]})
	domainName, ok := p.alloc.DomainOf(dst)
	if !ok {
		return false, nil
	}

	icmp := pkt[ihl:total]
	if icmp[0] != icmpEchoReq || icmp[1] != 0 {
		return false, nil
	}

	out := make([]byte, total)
	copy(out, pkt[:total])
	// Swap the addresses so the reply travels back to the client.
	copy(out[12:16], pkt[16:20])
	copy(out[16:20], pkt[12:16])
	out[8] = icmpTTL // TTL
	out[10], out[11] = 0, 0
	out[ihl] = icmpEchoReply
	out[ihl+1] = 0
	out[ihl+2], out[ihl+3] = 0, 0

	binary.BigEndian.PutUint16(out[ihl+2:], onesComplementSum(out[ihl:]))
	binary.BigEndian.PutUint16(out[10:], onesComplementSum(out[:ihl]))

	p.log().Debug("alias: icmp echo answered",
		zap.String("virtual_ip", dst.String()), zap.String("domain", domainName))
	return true, out
}

// onesComplementSum computes the RFC 1071 checksum of data. The caller stores
// the result in the place of the two zeroed checksum bytes.
func onesComplementSum(data []byte) uint16 {
	var sum uint32
	for len(data) >= 2 {
		sum += uint32(data[0])<<8 | uint32(data[1])
		data = data[2:]
	}
	if len(data) == 1 {
		sum += uint32(data[0]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}
