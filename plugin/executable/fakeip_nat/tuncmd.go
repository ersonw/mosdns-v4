package fakeipnat

import (
	"net/netip"
	"strconv"
)

// This file translates "give this device the reserved address and route the
// whole range into it" into the command line of each supported platform. The
// plans are pure data, so they are unit tested on any host; the per-platform
// files only decide which plan to run.

// effectiveTunMTU falls back to the Ethernet size when Init has not resolved a
// value (the native data path never builds a device, and plan tests build one
// without Init).
func effectiveTunMTU(mtu uint32) uint32 {
	if mtu == 0 {
		return defaultTunMTU
	}
	return mtu
}

// linuxCreateTunCommands requests a persistent tun device from iproute2. It is
// only run when the device does not exist yet.
func linuxCreateTunCommands(dev string) []tunCommand {
	return []tunCommand{
		{args: []string{"ip", "tuntap", "add", "dev", dev, "mode", "tun"}},
	}
}

// linuxConfigureTunCommands brings the device up and assigns the reserved
// address with the mask of the configured range. With that mask the kernel
// derives the connected route for the whole range on its own, so "ip r" shows
//
//	198.18.0.0/15 dev mth0 proto kernel scope link src 198.18.0.1
//
// and both the source selection and the next hop for the return path work
// without any extra route command.
func linuxConfigureTunCommands(dev, addr, cidr string, mtu uint32) []tunCommand {
	mtu = effectiveTunMTU(mtu)
	cmds := []tunCommand{
		// The MTU is written before the device comes up: the stack advertises
		// segments of that size to the client, so a device left at the Ethernet
		// default would keep handing out segments the outlet cannot carry.
		{args: []string{"ip", "link", "set", "dev", dev, "mtu", strconv.Itoa(int(mtu)), "up"}},
		{args: []string{"ip", "addr", "replace", addr + tunAddrMask(cidr), "dev", dev}},
	}
	// A host mask has no connected route, so the range is named explicitly.
	if tunAddrMask(cidr) == "/32" {
		cmds = append(cmds, tunCommand{args: []string{"ip", "route", "replace", cidr, "dev", dev, "src", addr}})
	}
	// The kernel keeps IPv6 enabled on a new interface and then sends its
	// own MLD/DAD packets into the device, which the IPv4-only stack can
	// only drop. Turning it off removes that noise; the failure is ignored
	// because a restricted netns may refuse sysctl writes.
	cmds = append(cmds, tunCommand{
		args:     []string{"sysctl", "-w", "net.ipv6.conf." + dev + ".disable_ipv6=1"},
		optional: true,
	})
	return cmds
}

// tunAddrMask returns the "/prefix" part of the configured range so the
// interface address carries the same mask. Init already validated the range;
// an unparsable value falls back to a host mask.
func tunAddrMask(cidr string) string {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil || !prefix.IsValid() {
		return "/32"
	}
	return "/" + strconv.Itoa(prefix.Bits())
}

// bsdConfigureTunCommands is shared by darwin and freebsd: ifconfig for the
// address, route for the range. BSD route has no "replace", so the old rule is
// removed first on a best effort basis.
//
// tun/utun interfaces are point-to-point, so ifconfig needs a destination
// address next to the local one; without it macOS answers
// "ioctl (SIOCAIFADDR): Destination address required". The peer address is set
// to the reserved address itself, which means "the far end is a black hole",
// and the whole fake range is then routed into the device. The host mask is
// /32 on purpose: the range route, not the interface netmask, decides what
// reaches the device, so no subnet is baked into the plugin - both the reserved
// address and the cidr are derived from the configured ipv4_range.
func bsdConfigureTunCommands(dev, addr, cidr string, mtu uint32) []tunCommand {
	mtu = effectiveTunMTU(mtu)
	return []tunCommand{
		{args: []string{"ifconfig", dev, "inet", addr, addr, "netmask", "255.255.255.255", "mtu", strconv.Itoa(int(mtu)), "up"}},
		{args: []string{"route", "delete", "-net", cidr}, optional: true},
		{args: []string{"route", "add", "-net", cidr, "-interface", dev}},
	}
}

// windowsConfigureTunCommands uses netsh, which is present on every supported
// Windows version and needs no extra tooling.
func windowsConfigureTunCommands(dev, addr, cidr string, mtu uint32) []tunCommand {
	mtu = effectiveTunMTU(mtu)
	return []tunCommand{
		{args: []string{"netsh", "interface", "ipv4", "set", "address",
			"name=" + dev, "source=static", "address=" + addr, "mask=255.255.255.255"}},
		{args: []string{"netsh", "interface", "ipv4", "set", "subinterface", dev,
			"mtu=" + strconv.Itoa(int(mtu)), "store=persistent"}},
		{args: []string{"netsh", "interface", "ipv4", "delete", "route",
			"prefix=" + cidr, "interface=" + dev}, optional: true},
		{args: []string{"netsh", "interface", "ipv4", "add", "route",
			"prefix=" + cidr, "interface=" + dev, "metric=1"}},
	}
}
