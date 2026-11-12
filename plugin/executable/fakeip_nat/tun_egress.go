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
	"strconv"
	"time"

	"go.uber.org/zap"
)

func (p *FakeIPNatPlugin) setupTunEgress() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// What this run is about to own. Anything a previous run recorded with a
	// different spec - an edited range, an edited table, or a run of the NAT
	// data path - is removed by its record before the new objects are written.
	keepFakeRule := ""
	if p.policyRuleSupported {
		keepFakeRule = fakeRangeRuleState(p.cidr, tunFakeRulePriority)
	}
	keepEgress := ""
	if !p.proxyActive {
		keepEgress = tunEgressState(p.tunRouteTable, p.cidr)
	}
	p.sweepRecordedTunState(ctx, keepFakeRule, keepEgress)

	// The fake range has to reach the device no matter how the host decides to
	// route or mark packet destinations: a gateway with its own policy routing
	// (VyOS marks every non-CN destination into an oversea table) intercepts the
	// fake addresses before main is ever consulted, and the packets leave the
	// machine through the tunnel instead of entering the device. This rule is
	// independent of the outlet, so it is installed before the proxy branch.
	fakeRule := ""
	if cleanup, ok := p.installFakeRangeRule(ctx); ok {
		p.tunFakeRuleCleanup = cleanup
		fakeRule = keepFakeRule
	}

	if p.proxyActive {
		p.L().Debug("tun egress: proxy carries the outlet, host routing left untouched")
		// The SNAT table belongs to the no-proxy outlet. A run that used it
		// before a proxy was configured leaves the table hooked in postrouting,
		// and this branch would never remove it.
		p.removeStaleTunSNAT(ctx)
		p.saveTunState(ctx, fakeRule, "")
		return
	}

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

	egress := ""
	if cleanup, ok := p.installTunEgressRoute(ctx); ok {
		p.tunEgressCleanup = cleanup
		egress = keepEgress
	}
	// Recorded only now, after the writes: a record must never describe an object
	// this run did not manage to install.
	p.saveTunState(ctx, fakeRule, egress)
	p.prepareDirectEgress()
	// The outlet now has its device (and, on linux, its range source); rewrite
	// that source on the way out so the gateway can route the answer back.
	if cleanup, ok := p.installTunSNAT(ctx); ok {
		prev := p.tunEgressCleanup
		p.tunEgressCleanup = func() {
			if prev != nil {
				prev()
			}
			cleanup()
		}
	}
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
// tunFakeRulePriority puts the fake-range decision ahead of every policy rule a
// gateway installs for its own traffic. VyOS marks non-CN destinations (which a
// 198.18/15 address always is) with fwmark 0xa and routes them into an oversea
// table at priority 10, so without this rule the fake addresses take the tunnel
// and the device never sees a packet.
const tunFakeRulePriority = 5

// fakeRangeRuleArgs is the single shape of the rule, used for add and delete so
// the two can never drift apart.
func fakeRangeRuleArgs(action, cidr string, prio int) []string {
	return []string{"rule", action, "to", cidr, "lookup", "main", "prio", strconv.Itoa(prio)}
}

// installFakeRangeRule pins every packet addressed inside the fake range to the
// main table, where the kernel route of the device lives. It deliberately
// ignores marks: whatever fwmark the host policy put on the packet, a fake
// destination only exists here and can only be answered by the stack.
func (p *FakeIPNatPlugin) installFakeRangeRule(ctx context.Context) (func(), bool) {
	if !p.policyRuleSupported {
		p.L().Debug("tun data path: this platform has no policy rules, the device route is the only match")
		return nil, false
	}
	args := fakeRangeRuleArgs("add", p.cidr, tunFakeRulePriority)
	delArgs := fakeRangeRuleArgs("del", p.cidr, tunFakeRulePriority)
	// A run that was killed leaves the rule behind; adding a second copy would
	// leave a duplicate nobody can tell apart.
	_, _ = p.runner.Run(ctx, "ip", delArgs...)
	if _, err := p.runner.Run(ctx, "ip", args...); err != nil {
		p.L().Warn("tun data path: installing the fake range rule failed",
			zap.String("to", p.cidr), zap.Int("prio", tunFakeRulePriority), zap.Error(err))
		return nil, false
	}
	p.L().Info("tun data path: fake range pinned to the main table",
		zap.String("to", p.cidr), zap.Int("prio", tunFakeRulePriority))

	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
		defer cancel()
		if _, err := p.runner.Run(ctx, "ip", delArgs...); err != nil {
			p.L().Debug("tun data path: removing the fake range rule failed",
				zap.String("to", p.cidr), zap.Error(err))
			return
		}
		p.L().Debug("tun data path: fake range rule removed", zap.String("to", p.cidr))
	}, true
}

func (p *FakeIPNatPlugin) stopTunEgress() {
	cleanup := p.tunEgressCleanup
	p.tunEgressCleanup = nil
	if cleanup != nil {
		cleanup()
	}
	fakeRule := p.tunFakeRuleCleanup
	p.tunFakeRuleCleanup = nil
	if fakeRule != nil {
		fakeRule()
	}
	// The objects are gone, so the record that named them is too. A crash before
	// this point leaves the record in place, which is exactly what the next run
	// needs to remove them.
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()
	p.clearTunState(ctx)
}

// tunRoutePlan is the command line that pins the fake range to a dedicated
// routing table. It is pure data so it can be checked on any host, and
// installTunEgressRoute only has to run it.
//
//	ip route replace default via <hop> dev <dev> table <table>
//	ip rule del  from <cidr> lookup <table>            (drops the older shape)
//	ip rule del  from <cidr> to !<cidr> lookup <table> (best effort)
//	ip rule add  from <cidr> to !<cidr> lookup <table>
//
// The rule must skip packets that are aimed at the range itself: the client
// connecting to a fake ip leaves its socket with the reserved source address,
// and without the destination check that packet would be pulled into the
// egress table and sent straight out of the physical interface, bypassing the
// tun entirely.
func tunRoutePlan(cidr, hop, dev, table, prio string) [][]string {
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
	// prio is optional. When mark routing is on, the outlet rule has to be
	// consulted before "fwmark <mark> lookup <table>": otherwise the sockets the
	// stack opens are marked again and steered back into the device.
	add := []string{"ip", "rule", "add", "from", cidr, "to", "!", cidr, "lookup", table}
	if prio != "" {
		add = append(add, "prio", prio)
	}
	return [][]string{
		route,
		{"ip", "rule", "del", "from", cidr, "lookup", table},
		{"ip", "rule", "del", "from", cidr, "to", "!", cidr, "lookup", table},
		add,
	}
}

// dialUDP opens the outbound datagram socket. socks5 and trojan outlets carry
// UDP themselves (see egress.go: socks5Egress.dialUDP / trojanEgress.dialUDP);
// an outlet that cannot, i.e. plain http CONNECT, falls back to a direct socket
// so DNS over UDP keeps working.
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
