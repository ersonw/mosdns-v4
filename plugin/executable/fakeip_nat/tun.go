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
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
	"strings"

	"go.uber.org/zap"
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

// pickTunName reuses the device that already carries the reserved address, or
// takes the lowest free index. Both decisions come from two whole-system
// listings instead of one probe per candidate name: a box that collected a few
// dozen mth devices across restarts used to spend tens of seconds in here, and
// that time is taken out of every startup - the socket layer only answers after
// Init returns.
func (p *FakeIPNatPlugin) pickTunName(ctx context.Context) (string, error) {
	addr := p.reservedFakeIP()
	links, err := p.runner.Run(ctx, "ip", "-o", "link", "show")
	if err != nil {
		return "", fmt.Errorf("list links: %w", err)
	}
	existing := tunDevices(links, defaultTunBase)
	if addrs, aerr := p.runner.Run(ctx, "ip", "-o", "addr", "show"); aerr == nil {
		if name := tunDeviceWithAddr(addrs, addr); name != "" {
			p.L().Debug("fakeip nat: reusing leftover tun device with the reserved address",
				zap.String("dev", name), zap.String("addr", addr))
			return name, nil
		}
	}
	for i := 0; i < maxAutoTunIdx; i++ {
		name := fmt.Sprintf("%s%d", defaultTunBase, i)
		if _, taken := existing[name]; taken {
			continue
		}
		p.L().Debug("fakeip nat: free tun name found", zap.String("dev", name), zap.Int("index", i))
		return name, nil
	}
	return "", fmt.Errorf("no free tun device name in %s0..%s%d", defaultTunBase, defaultTunBase, maxAutoTunIdx-1)
}

// tunDevices returns the base-prefixed device names in one `ip -o link show`
// listing, keyed by name for the free-index search.
func tunDevices(out, base string) map[string]struct{} {
	names := make(map[string]struct{}, 8)
	for _, line := range strings.Split(out, "\n") {
		// One device per line: "<index>: <name>: <flags> ..." or
		// "<index>: <name>@<peer>: ..." for a veth.
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		name := tunDeviceField(f[1])
		if !tunBaseNameMatch(name, base) {
			continue
		}
		names[name] = struct{}{}
	}
	return names
}

// tunBaseNameMatch reports whether name is <base> followed by digits only, so
// "mth" and "mth0" match while "mthx" or "mth0old" do not.
func tunBaseNameMatch(name, base string) bool {
	if !strings.HasPrefix(name, base) {
		return false
	}
	rest := name[len(base):]
	if rest == "" {
		return false
	}
	for _, r := range rest {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// tunDeviceWithAddr finds the device one `ip -o addr show` listing reports with
// the reserved address.
func tunDeviceWithAddr(out, addr string) string {
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 3 {
			continue
		}
		name := tunDeviceField(f[1])
		if !tunBaseNameMatch(name, defaultTunBase) {
			continue
		}
		if strings.Contains(line, "inet "+addr+"/") {
			return name
		}
	}
	return ""
}

// tunDeviceField cleans one name field of an `ip -o` listing: the link listing
// keeps a trailing colon and a veth carries "@<peer>".
func tunDeviceField(raw string) string {
	name := strings.TrimSuffix(raw, ":")
	if idx := strings.IndexByte(name, '@'); idx >= 0 {
		name = name[:idx]
	}
	return name
}
