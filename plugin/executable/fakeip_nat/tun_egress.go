package fakeipnat

// This file pins the tun outlet to next_hop / next_hop_dev when no proxy is
// configured. The userspace stack opens brand new sockets for every flow, so
// the host routing decision applies to them, not to the fake ip packets. A
// dedicated routing table plus an ip rule for the range makes those sockets
// leave through the configured gateway; the source address is the range address
// the tun device already owns.
//
// With a proxy the outlet is the proxy link itself, so no host route is
// installed: the proxy socket must reach the proxy server through the normal
// network.

import (
	"context"
	"net"
	"net/netip"
	"time"

	"go.uber.org/zap"
)

func (p *FakeIPNatPlugin) setupTunEgress() {
	if p.proxyActive {
		p.L().Debug("tun egress: proxy carries the outlet, host routing left untouched")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Unset options mean "follow the host": the plugin reads the system
	// default route and pins its own table to the same gateway and device, so
	// the fake range never falls back to a different path than the host.
	hop, dev := p.nextHop, p.nextHopDev
	if hop == "" || dev == "" {
		sysHop, sysDev := p.systemDefaultRoute(ctx)
		if hop == "" {
			hop = sysHop
		}
		if dev == "" {
			dev = sysDev
		}
	}
	if hop == "" && dev == "" {
		p.L().Warn("tun egress: neither next_hop nor the system default route is available, route table not installed")
		return
	}
	p.tunEgressHop, p.tunEgressDev = hop, dev
	p.L().Debug("tun egress: outlet target resolved",
		zap.String("next_hop", hop), zap.String("next_hop_dev", dev),
		zap.String("route_table", p.tunRouteTable), zap.String("from", p.cidr))

	if cleanup, ok := p.installTunEgressRoute(ctx); ok {
		p.tunEgressCleanup = cleanup
	}
	p.prepareDirectEgress()
}

// prepareDirectEgress binds the direct outlet to the range address and the
// configured interface. The address is owned by the tun device, so every dial
// leaves from the range instead of the host's primary address, which is the
// same source the data path already rewrites the packets to.
func (p *FakeIPNatPlugin) prepareDirectEgress() {
	d, ok := p.egress.(*directEgress)
	if !ok {
		return
	}
	d.dev = p.tunEgressDev
	if !sourceBindingSupported {
		// Without a host SNAT layer the kernel would reject a source address
		// owned by the tun device on the physical interface, so the socket
		// keeps the host address and only the device is pinned.
		p.L().Info("tun egress: direct outlet bound",
			zap.String("dev", p.tunEgressDev), zap.String("source", "host address"))
		return
	}
	src := p.reservedAddr()
	if !canBindAddress(src) {
		p.L().Warn("tun egress: range address cannot be bound locally, keeping the host source address",
			zap.String("addr", src.String()))
		return
	}
	d.local = src
	p.L().Info("tun egress: direct outlet bound",
		zap.String("source", src.String()), zap.String("dev", p.tunEgressDev))
}

// canBindAddress reports whether the kernel accepts addr as a local source.
func canBindAddress(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	l, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IP(addr.AsSlice()), Port: 0})
	if err != nil {
		return false
	}
	_ = l.Close()
	l4, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IP(addr.AsSlice()), Port: 0})
	if err != nil {
		return false
	}
	_ = l4.Close()
	return true
}

// stopTunEgress removes the rule installed for the outlet. The table's default
// route is deleted with it; nothing else is touched.
func (p *FakeIPNatPlugin) stopTunEgress() {
	cleanup := p.tunEgressCleanup
	p.tunEgressCleanup = nil
	if cleanup != nil {
		cleanup()
	}
}

// tunRoutePlan is the command line that pins the fake range to a dedicated
// routing table. It is pure data so it can be checked on any host, and
// installTunEgressRoute only has to run it.
//
//	ip route replace default via <hop> dev <dev> table <table>
//	ip rule del  from <cidr> lookup <table>   (best effort, drops a stale rule)
//	ip rule add  from <cidr> lookup <table>
func tunRoutePlan(cidr, hop, dev, table string) [][]string {
	var route []string
	switch {
	case hop != "" && dev != "":
		route = []string{"ip", "route", "replace", "default", "via", hop, "dev", dev, "table", table}
	case hop != "":
		route = []string{"ip", "route", "replace", "default", "via", hop, "table", table}
	case dev != "":
		route = []string{"ip", "route", "replace", "default", "dev", dev, "table", table}
	default:
		return nil
	}
	return [][]string{
		route,
		{"ip", "rule", "del", "from", cidr, "lookup", table},
		{"ip", "rule", "add", "from", cidr, "lookup", table},
	}
}

// dialUDP opens the outbound datagram socket. A proxy outlet that cannot carry
// UDP (socks5/http/trojan in this build) falls back to a direct socket so DNS
// over UDP keeps working.
func (p *FakeIPNatPlugin) dialUDP(ctx context.Context, target string) (net.Conn, error) {
	c, err := p.egress.DialContext(ctx, "udp", target)
	if err == nil {
		return c, nil
	}
	if !p.proxyActive {
		return nil, err
	}
	p.L().Debug("tun udp: proxy outlet does not carry udp, dialing directly",
		zap.String("target", target), zap.Error(err))
	var d net.Dialer
	return d.DialContext(ctx, "udp", target)
}
