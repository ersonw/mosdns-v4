package fakeipnat

// This file translates "give this device the reserved address and route the
// whole range into it" into the command line of each supported platform. The
// plans are pure data, so they are unit tested on any host; the per-platform
// files only decide which plan to run.

// linuxCreateTunCommands requests a persistent tun device from iproute2. It is
// only run when the device does not exist yet.
func linuxCreateTunCommands(dev string) []tunCommand {
	return []tunCommand{
		{args: []string{"ip", "tuntap", "add", "dev", dev, "mode", "tun"}},
	}
}

// linuxConfigureTunCommands brings the device up, assigns the reserved address
// as a single host and routes the range into the device.
func linuxConfigureTunCommands(dev, addr, cidr string) []tunCommand {
	return []tunCommand{
		{args: []string{"ip", "link", "set", "dev", dev, "up"}},
		{args: []string{"ip", "addr", "replace", addr + "/32", "dev", dev}},
		{args: []string{"ip", "route", "replace", cidr, "dev", dev}},
	}
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
func bsdConfigureTunCommands(dev, addr, cidr string) []tunCommand {
	return []tunCommand{
		{args: []string{"ifconfig", dev, "inet", addr, addr, "netmask", "255.255.255.255", "up"}},
		{args: []string{"route", "delete", "-net", cidr}, optional: true},
		{args: []string{"route", "add", "-net", cidr, "-interface", dev}},
	}
}

// windowsConfigureTunCommands uses netsh, which is present on every supported
// Windows version and needs no extra tooling.
func windowsConfigureTunCommands(dev, addr, cidr string) []tunCommand {
	return []tunCommand{
		{args: []string{"netsh", "interface", "ipv4", "set", "address",
			"name=" + dev, "source=static", "address=" + addr, "mask=255.255.255.255"}},
		{args: []string{"netsh", "interface", "ipv4", "delete", "route",
			"prefix=" + cidr, "interface=" + dev}, optional: true},
		{args: []string{"netsh", "interface", "ipv4", "add", "route",
			"prefix=" + cidr, "interface=" + dev, "metric=1"}},
	}
}
