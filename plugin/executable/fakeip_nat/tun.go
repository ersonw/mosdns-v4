package fakeipnat

// This file owns the platform independent part of the TUN data path:
// `use_tun: true` switches the plugin away from per-domain nftables DNAT and
// routes the whole ipv4_range into a device whose address is the first host of
// the range. That address is reserved by the allocator (see allocateFakeIP), so
// no domain is ever mapped onto the device itself.
//
// Device creation, address assignment and the range route are platform
// specific and live in tunio_<goos>.go; the packet pump and the userspace stack
// are shared by every target.

import (
	"encoding/binary"
	"net/netip"
)

const (
	// Auto-requested devices are named <base>0, <base>1, ... and the first free
	// index is used.
	defaultTunBase = "mth"
	maxAutoTunIdx  = 64
	// reservedHostOffset is the first host of ipv4_range: the tun device owns
	// it and the allocator never hands it out to a domain.
	reservedHostOffset = 1
)

// reservedAddr is the first host of the range: the tun device owns it, and
// the allocator starts one address after it.
func (p *FakeIPNatPlugin) reservedAddr() netip.Addr {
	base := p.prefix.Addr().As4()
	baseUint := binary.BigEndian.Uint32(base[:])
	var a [4]byte
	binary.BigEndian.PutUint32(a[:], baseUint+reservedHostOffset)
	return netip.AddrFrom4(a)
}

// reservedFakeIP is the string form of reservedAddr, used on command lines.
func (p *FakeIPNatPlugin) reservedFakeIP() string {
	return p.reservedAddr().String()
}
