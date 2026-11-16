package fakeipnat

// Real-destination capture.
//
// The fake range only covers names that were asked through this resolver. An
// app that ships its own address list - the usual reason a mobile client "does
// not use the proxy" while a browser on the same network works - connects to a
// real edge address that never entered the mapping table. Those packets reach
// the host's own routing table and leave the machine directly, which in a
// restricted network means the handshake goes out and nothing comes back.
//
// A configured capture prefix closes that hole: the prefix is routed into the
// device, the read loop accepts it, and the flow is dialed through the outlet
// like any other. The address itself is the target, so no mapping is needed.

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"time"

	"go.uber.org/zap"
)

// loadCapturePrefixes reads the configured capture prefixes. Inline entries and
// a file may be combined; blank lines and comments are skipped so the file can
// carry notes next to the ranges.
func loadCapturePrefixes(inline []string, file string) ([]netip.Prefix, error) {
	raw := make([]string, 0, len(inline)+8)
	raw = append(raw, inline...)

	if path := strings.TrimSpace(file); path != "" {
		body, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read capture_file %q: %w", path, err)
		}
		raw = append(raw, strings.Split(string(body), "\n")...)
	}

	out := make([]netip.Prefix, 0, len(raw))
	seen := make(map[netip.Prefix]struct{}, len(raw))
	for _, line := range raw {
		entry := strings.TrimSpace(line)
		if entry == "" || strings.HasPrefix(entry, "#") {
			continue
		}
		// A bare address is accepted as a single host so an operator can pin one
		// edge without writing /32.
		if addr, err := netip.ParseAddr(entry); err == nil {
			entry = netip.PrefixFrom(addr, addr.BitLen()).String()
		}
		pfx, err := netip.ParsePrefix(entry)
		if err != nil {
			return nil, fmt.Errorf("capture prefix %q: %w", entry, err)
		}
		if !pfx.Addr().Is4() {
			return nil, fmt.Errorf("capture prefix %q: only IPv4 is supported", entry)
		}
		pfx = pfx.Masked()
		if _, ok := seen[pfx]; ok {
			continue
		}
		seen[pfx] = struct{}{}
		out = append(out, pfx)
	}
	return out, nil
}

// capturesAddr reports whether a real destination belongs to a capture prefix.
// The list is fixed at startup, so a read needs no lock.
func (p *FakeIPNatPlugin) capturesAddr(addr netip.Addr) bool {
	if len(p.capturePrefixes) == 0 || !addr.IsValid() || !addr.Is4() {
		return false
	}
	for _, pfx := range p.capturePrefixes {
		if pfx.Contains(addr) {
			return true
		}
	}
	return false
}

// installCaptureRoutes writes one route per capture prefix into the device, in
// the same table the fake range uses. Each prefix is recorded in the ledger
// first, so a stop, a crash or a configuration change removes exactly these
// routes and nothing the operator configured by hand.
func (p *FakeIPNatPlugin) installCaptureRoutes() {
	if len(p.capturePrefixes) == 0 || p.tunDev == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	installed := 0
	for _, pfx := range p.capturePrefixes {
		prefix := pfx.String()
		// The pin rule installed below looks up the main table, so the route has
		// to live there. A named host table would leave the rule pointing at a
		// table the prefix is not in, and the packet would fall through to the
		// host's own policy routing.
		commands := routeWriteCommands(prefix, "", p.tunDev, "main")
		if len(commands) == 0 {
			p.L().Warn("capture prefix skipped, this platform has no managed route support",
				zap.String("prefix", prefix))
			continue
		}
		for _, cmd := range commands {
			if _, err := p.runner.Run(ctx, cmd[0], cmd[1:]...); err != nil {
				p.L().Warn("capture route failed",
					zap.String("prefix", prefix), zap.String("dev", p.tunDev), zap.Error(err))
				continue
			}
			installed++
			if p.ledger == nil {
				p.ledger = newRouteLedger()
			}
			p.ledger.remember(ledgerRoute{prefix: prefix, dev: p.tunDev, routeTable: "main"})
		}
	}
	p.L().Info("fakeip nat: capture prefixes routed into the device",
		zap.Int("prefixes", len(p.capturePrefixes)),
		zap.Int("routes", installed),
		zap.String("dev", p.tunDev),
		zap.String("table", "main"))
	p.installCaptureRules(ctx)
}

// installCaptureRules pins every capture prefix to the main table, the same way
// the fake range is pinned. Without it a host that marks non-domestic
// destinations - the usual VyOS setup - sends the packet into its own policy
// table before main is ever consulted, and the device route above never matches.
// Each add is preceded by a delete so a run killed mid-flight cannot leave a
// duplicate that no later run can tell apart.
func (p *FakeIPNatPlugin) installCaptureRules(ctx context.Context) {
	if !p.policyRuleSupported || len(p.capturePrefixes) == 0 {
		return
	}
	added := make([]string, 0, len(p.capturePrefixes))
	for _, pfx := range p.capturePrefixes {
		prefix := pfx.String()
		delArgs := fakeRangeRuleArgs("del", prefix, tunFakeRulePriority)
		_, _ = p.runner.Run(ctx, "ip", delArgs...)
		args := fakeRangeRuleArgs("add", prefix, tunFakeRulePriority)
		if _, err := p.runner.Run(ctx, "ip", args...); err != nil {
			p.L().Warn("tun data path: installing a capture rule failed",
				zap.String("to", prefix), zap.Int("prio", tunFakeRulePriority), zap.Error(err))
			continue
		}
		added = append(added, prefix)
	}
	if len(added) == 0 {
		return
	}
	p.captureRuleCleanup = func() {
		ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
		defer cancel()
		for _, prefix := range added {
			if _, err := p.runner.Run(ctx, "ip", fakeRangeRuleArgs("del", prefix, tunFakeRulePriority)...); err != nil {
				p.L().Debug("tun data path: removing a capture rule failed",
					zap.String("to", prefix), zap.Error(err))
			}
		}
	}
	p.L().Info("tun data path: capture prefixes pinned to the main table",
		zap.Int("prefixes", len(added)), zap.Int("prio", tunFakeRulePriority))
}
