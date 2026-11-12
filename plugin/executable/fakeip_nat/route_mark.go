package fakeipnat

// Destination-mark routing for the non-tun data path.
//
// The previous shape wrote one /32 host route per resolved real ip into the
// configured table, which by default is "main". On a gateway that resolves a
// few thousand names the host table fills up with entries the operator cannot
// tell apart from their own, and neither a reload nor a restart is guaranteed
// to remove them again.
//
// Marking by destination moves that state out of the routing table entirely:
//
//   - a resolved real ip only enters the nft set real_ipv4, never a route;
//   - nft marks every packet whose destination is in that set, in the
//     prerouting hook and in the output hook;
//   - one `ip rule fwmark <mark> lookup <table>` sends the marked packets into
//     a dedicated table that holds nothing but a default route towards the
//     configured gateway.
//
// Non-mapped traffic never consults that table, and cleanup is one rule delete
// plus one table flush, so nothing can be left behind.

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"go.uber.org/zap"
)

// markSetName is the nft set that carries the destinations to mark. It lives
// in the same nft table as the DNAT map, so fake-ip and realip mode share one
// place to look.
const markSetName = "real_ipv4"

// markRoutingEnabled reports whether the operator asked for mark routing.
func (p *FakeIPNatPlugin) markRoutingEnabled() bool { return p.routeMark != 0 }

// markActiveNow reports whether mark routing is fully installed: table, set,
// mark rules, default route and the ip rule. Calling it before setup finished
// is safe and simply reports false.
func (p *FakeIPNatPlugin) markActiveNow() bool {
	p.markMu.Lock()
	defer p.markMu.Unlock()
	return p.markActive
}

// markCommand is one nft invocation plus whether a failure is expected.
type markCommand struct {
	args     []string
	tolerate bool
}

// ensureMarkTable creates the nft objects mark routing needs: the set that
// names the destinations, and the two chains that mark them.
//
// The chains and the set are dropped and recreated on every start instead of
// being probed one by one: a process that died can leave the objects behind,
// and adding a second copy of the same rule would mark the packet twice for no
// reason. Recreating is idempotent by construction and costs a few milliseconds
// before the first packet arrives.
func (p *FakeIPNatPlugin) ensureMarkTable(ctx context.Context, table string) error {
	p.markMu.Lock()
	defer p.markMu.Unlock()
	if p.markReady {
		return nil
	}

	mark := strconv.FormatUint(uint64(p.routeMark), 10)
	setup := []markCommand{
		{args: []string{"add", "table", "ip", table}, tolerate: true},
		{args: []string{"delete", "chain", "ip", table, "mark_prerouting"}, tolerate: true},
		{args: []string{"delete", "chain", "ip", table, "mark_output"}, tolerate: true},
		{args: []string{"delete", "set", "ip", table, markSetName}, tolerate: true},
		// The timeout keeps the set from growing forever: an address that is no
		// longer used is refreshed by nobody and expires on its own, so there is
		// no sweep loop to maintain.
		{args: []string{"add", "set", "ip", table, markSetName,
			"{ type ipv4_addr; flags timeout; timeout 1h; }"}},
		// Priority 0 puts the mark after the DNAT chain (-100): in fake-ip mode
		// the destination is the real ip by then, so one set serves both data
		// planes. The routing lookup of a forwarded packet happens after the
		// prerouting hook returns, so a mark set here still decides the route.
		{args: []string{"add", "chain", "ip", table, "mark_prerouting",
			"{ type filter hook prerouting priority 0; policy accept; }"}},
		{args: []string{"add", "rule", "ip", table, "mark_prerouting",
			"ip", "daddr", "@" + markSetName, "meta", "mark", "set", mark}},
		// Locally generated traffic is routed before the output hook runs, so
		// this chain has to be of type "route": that type re-runs the lookup
		// when a hook changes the mark.
		{args: []string{"add", "chain", "ip", table, "mark_output",
			"{ type route hook output priority 0; policy accept; }"}},
		{args: []string{"add", "rule", "ip", table, "mark_output",
			"ip", "daddr", "@" + markSetName, "meta", "mark", "set", mark}},
	}

	created := 0
	for _, cmd := range setup {
		_, err := p.runner.Run(ctx, "nft", cmd.args...)
		if err == nil {
			created++
			continue
		}
		if cmd.tolerate {
			// A missing chain, set or table is the normal first-run case.
			p.L().Debug("route mark: nft object absent before setup",
				zap.Strings("cmd", cmd.args), zap.Error(err))
			continue
		}
		return fmt.Errorf("nft %s: %w", strings.Join(cmd.args, " "), err)
	}
	p.markReady = true
	p.L().Debug("route mark: nft mark objects ready",
		zap.String("nft_table", table), zap.String("set", markSetName), zap.Int("commands", created))
	return nil
}

// setupMarkRouting installs the whole mark path: nft objects, the default
// route in the dedicated table, and the ip rule that points marked packets at
// it. A failure here means the data path falls back to host routes, so the
// caller only logs it instead of failing the plugin.
func (p *FakeIPNatPlugin) setupMarkRouting(ctx context.Context) error {
	table := p.nftTableName()
	if err := p.ensureMarkTable(ctx, table); err != nil {
		return err
	}

	hop, dev := p.nextHop, p.nextHopDev
	if hop == "" && dev == "" {
		hop, dev = p.systemDefaultRoute(ctx)
	}
	if hop == "" && dev == "" {
		return fmt.Errorf("no next hop and no device to route marked traffic")
	}

	// The dedicated table holds one route only: everything that arrives here is
	// already known to belong to a mapped destination, so a default towards the
	// configured gateway is exactly the intent. Per-address routes would only
	// duplicate it.
	routeArgs := []string{"route", "replace", "default"}
	if hop != "" {
		routeArgs = append(routeArgs, "via", hop)
	}
	if dev != "" {
		routeArgs = append(routeArgs, "dev", dev)
	}
	routeArgs = append(routeArgs, "table", p.routeTable)
	if _, err := p.runner.Run(ctx, "ip", routeArgs...); err != nil {
		return fmt.Errorf("ip %s: %w", strings.Join(routeArgs, " "), err)
	}

	// Deleting a rule that is not there is the normal case, so it is not an
	// error; adding the same rule twice would leave a duplicate behind.
	_, _ = p.runner.Run(ctx, "ip", p.markRuleArgs("del")...)
	if _, err := p.runner.Run(ctx, "ip", p.markRuleArgs("add")...); err != nil {
		return fmt.Errorf("ip %s: %w", strings.Join(p.markRuleArgs("add"), " "), err)
	}

	p.markMu.Lock()
	p.markActive = true
	p.markMu.Unlock()
	p.L().Info("route mark: destination mark routing installed",
		zap.String("nft_table", table), zap.Uint32("mark", p.routeMark),
		zap.String("route_table", p.routeTable), zap.String("next_hop", hop),
		zap.String("dev", dev), zap.Int("rule_priority", p.routeRulePriority))
	return nil
}

// markRuleArgs is the single shape of the policy rule, used for add and delete
// so the two can never drift apart.
func (p *FakeIPNatPlugin) markRuleArgs(action string) []string {
	return []string{
		"rule", action,
		"fwmark", strconv.FormatUint(uint64(p.routeMark), 10),
		"lookup", p.routeTable,
		"prio", strconv.Itoa(p.routeRulePriority),
	}
}

// markRealIP adds one destination to the set that nft marks. This is the
// replacement for writing a /32 host route: the address never touches a
// routing table.
func (p *FakeIPNatPlugin) markRealIP(ctx context.Context, ip string) error {
	table := p.nftTableName()
	if err := p.ensureMarkTable(ctx, table); err != nil {
		return err
	}
	if _, err := p.runner.Run(ctx, "nft", "add", "element", "ip", table, markSetName, "{ "+ip+" }"); err != nil {
		return fmt.Errorf("nft add element %s %s %s: %w", table, markSetName, ip, err)
	}
	return nil
}

// cleanupMarkRouting removes the policy rule and the default route of the
// dedicated table, then marks the path as gone. The nft objects are dropped by
// cleanupDataPath together with the rest of the table.
func (p *FakeIPNatPlugin) cleanupMarkRouting(ctx context.Context) {
	if !p.markRoutingEnabled() {
		return
	}
	if _, err := p.runner.Run(ctx, "ip", p.markRuleArgs("del")...); err != nil {
		p.L().Debug("route mark: removing policy rule failed", zap.Strings("cmd", p.markRuleArgs("del")), zap.Error(err))
	}
	delRoute := []string{"route", "del", "default", "table", p.routeTable}
	if _, err := p.runner.Run(ctx, "ip", delRoute...); err != nil {
		p.L().Debug("route mark: removing default route failed", zap.Strings("cmd", delRoute), zap.Error(err))
	}
	p.markMu.Lock()
	p.markActive = false
	p.markReady = false
	p.markMu.Unlock()
	p.L().Info("route mark: destination mark routing removed",
		zap.Uint32("mark", p.routeMark), zap.String("route_table", p.routeTable))
}
