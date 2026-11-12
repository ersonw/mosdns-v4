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
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"go.uber.org/zap"
)

// markSetName is the nft set that carries the destinations to mark. It lives
// in the same nft table as the DNAT map, so fake-ip and realip mode share one
// place to look.
const markSetName = "real_ipv4"

// markRoutingEnabled reports whether mark routing applies to this run, and it is
// a run-time answer because the proxy decides part of it.
//
//   - NAT data path: the mark replaces the per-address host routes.
//   - tun + realip: the answers keep their real addresses, so the mark is what
//     decides those destinations belong to the plugin and have to enter the
//     device. A proxy does not change that, the device is still the way in.
//   - tun + fakeip: the answers are fake and the whole range enters the device
//     by route, so the only destinations worth marking are the real ones the
//     stack dials itself; the mark sends them to next_hop/next_hop_dev. A proxy
//     dials those for the plugin instead, so the mark would only fight it.
func (p *FakeIPNatPlugin) markRoutingEnabled() bool {
	if p.routeMark == 0 {
		return false
	}
	if p.useTun && !p.realIP && p.proxyActive {
		return false
	}
	return true
}

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
			"ip", "daddr", "@" + markSetName, "ip", "saddr", "!=", p.cidr,
			"meta", "mark", "set", mark}},
		// Locally generated traffic is routed before the output hook runs, so
		// this chain has to be of type "route": that type re-runs the lookup
		// when a hook changes the mark.
		{args: []string{"add", "chain", "ip", table, "mark_output",
			"{ type route hook output priority 0; policy accept; }"}},
		// The source condition keeps the plugin's own outlet sockets out of the
		// set they are marking: those bind a source inside the range, and a mark
		// on them would send the socket that carries the traffic back into the
		// device it came from.
		{args: []string{"add", "rule", "ip", table, "mark_output",
			"ip", "daddr", "@" + markSetName, "ip", "saddr", "!=", p.cidr,
			"meta", "mark", "set", mark}},
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

	// Two shapes reach this point:
	//   NAT path: the marked destinations leave through the configured gateway.
	//   tun + realip: marked destinations are routed into the device the plugin
	//   already owns, which is where the proxy - or, without one, the pinned
	//   outlet route - takes over. Pointing the table at the next hop instead
	//   would bypass the device entirely, which is exactly what this mode
	//   exists to avoid.
	var hop, dev string
	if p.useTun && p.realIP {
		// The marked destinations are the real answers a client asks for: they
		// have to enter the device, where the proxy - or the pinned outlet
		// route - takes over.
		dev = p.tunDev
		if dev == "" {
			return fmt.Errorf("mark routing in tun mode needs the tun device, which is not up")
		}
	} else {
		hop, dev = p.nextHop, p.nextHopDev
		if hop == "" && dev == "" {
			hop, dev = p.systemDefaultRoute(ctx)
		}
		if hop == "" && dev == "" {
			return fmt.Errorf("no next hop and no device to route marked traffic")
		}
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

// markRealIPs adds several destinations at once. One nft call per answer keeps
// the tun + fakeip path as cheap as the NAT path's per-address writes.
func (p *FakeIPNatPlugin) markRealIPs(ctx context.Context, ips []string) error {
	if len(ips) == 0 {
		return nil
	}
	table := p.nftTableName()
	if err := p.ensureMarkTable(ctx, table); err != nil {
		return err
	}
	element := "{ " + strings.Join(ips, ", ") + " }"
	if _, err := p.runner.Run(ctx, "nft", "add", "element", "ip", table, markSetName, element); err != nil {
		return fmt.Errorf("nft add element %s %s: %w", table, markSetName, err)
	}
	return nil
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
	if p.routeMark == 0 {
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

// The nft object names the self-check looks for. They are spelled here as
// constants because verifyMarkRouting reads them back from the kernel and must
// not drift from what ensureMarkTable created.
const (
	markPreroutingChain = "mark_prerouting"
	markOutputChain     = "mark_output"
)

// markCheck is what the startup self-check sees on the live system.
type markCheck struct {
	SetExists    bool
	SetSize      int
	Chains       map[string]bool
	RuleExists   bool
	DefaultRoute bool
}

// verifyMarkRouting reads the four installed objects back from the kernel: the
// nft set and its two chains, the policy rule, and the default route of the
// dedicated table. Installing them is not the same as them being there — a
// permission problem, a VyOS-managed table or an outdated binary all leave the
// plugin running while traffic quietly keeps falling back to host routes — so
// the shape is read back instead of assumed.
func (p *FakeIPNatPlugin) verifyMarkRouting(ctx context.Context) markCheck {
	var c markCheck
	table := p.nftTableName()

	// One listing covers the set and both chains; nft exits non-zero when the
	// table itself is gone, which is exactly the case worth reporting.
	if out, err := p.runner.Run(ctx, "nft", "-j", "list", "table", "ip", table); err == nil {
		c.SetExists, c.SetSize, c.Chains = parseMarkTable(out)
	}
	if out, err := p.runner.Run(ctx, "ip", "rule", "show"); err == nil {
		c.RuleExists = markRulePresent(out, p.routeMark, p.routeTable)
	}
	if out, err := p.runner.Run(ctx, "ip", "route", "show", "table", p.routeTable); err == nil {
		c.DefaultRoute = defaultRoutePresent(out)
	}
	return c
}

// reportMarkRouting writes the self-check into the log: one Info line when the
// mark path is complete, one Warn line naming the missing objects otherwise.
func (p *FakeIPNatPlugin) reportMarkRouting(ctx context.Context) {
	check := p.verifyMarkRouting(ctx)
	chains := check.Chains[markPreroutingChain] && check.Chains[markOutputChain]
	fields := []zap.Field{
		zap.Uint32("mark", p.routeMark),
		zap.String("route_table", p.routeTable),
		zap.Int("rule_priority", p.routeRulePriority),
		zap.Bool("set", check.SetExists),
		zap.Int("set_size", check.SetSize),
		zap.Bool("mark_chains", chains),
		zap.Bool("ip_rule", check.RuleExists),
		zap.Bool("default_route", check.DefaultRoute),
	}
	if check.SetExists && chains && check.RuleExists && check.DefaultRoute {
		p.L().Info("route mark: startup check passed", fields...)
		return
	}
	p.L().Warn("route mark: startup check found the mark path incomplete; traffic may fall back to host routes", fields...)
}

// parseMarkTable reads a `nft -j list table` document and reports whether the
// mark set exists, how many addresses it holds, and which chains are present.
// The walk is shape-tolerant on purpose: nft wraps every object in its own key
// and the exact nesting differs between releases.
func parseMarkTable(out string) (bool, int, map[string]bool) {
	chains := map[string]bool{}
	if strings.TrimSpace(out) == "" {
		return false, 0, chains
	}
	var doc any
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		// nft prints a plain error, not JSON, when the table is missing.
		return false, 0, chains
	}

	hasSet := false
	size := 0
	var walk func(any)
	walk = func(v any) {
		switch t := v.(type) {
		case map[string]any:
			if set, ok := t["set"].(map[string]any); ok {
				if name, _ := set["name"].(string); name == markSetName {
					hasSet = true
					size = setElementCount(set)
				}
			}
			if chain, ok := t["chain"].(map[string]any); ok {
				if name, _ := chain["name"].(string); name != "" {
					chains[name] = true
				}
			}
			for _, val := range t {
				walk(val)
			}
		case []any:
			for _, item := range t {
				walk(item)
			}
		}
	}
	walk(doc)
	return hasSet, size, chains
}

// setElementCount counts the members of an nft set. An absent element list and
// an empty one both mean zero addresses, which is the normal state right after
// the set is recreated at startup.
func setElementCount(set map[string]any) int {
	for _, key := range []string{"elem", "elements"} {
		if arr, ok := set[key].([]any); ok {
			return len(arr)
		}
	}
	return 0
}

// markRulePresent looks for `fwmark <mark> lookup <table>` in `ip rule show`.
// The kernel prints the mark in hex and the table as a number unless a name is
// registered, so both spellings are accepted.
func markRulePresent(out string, mark uint32, table string) bool {
	hexMark := "0x" + strconv.FormatUint(uint64(mark), 16)
	decMark := strconv.FormatUint(uint64(mark), 10)
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		var fwmark, lookup string
		for i, field := range fields {
			switch field {
			case "fwmark":
				if i+1 < len(fields) {
					fwmark = strings.SplitN(fields[i+1], "/", 2)[0]
				}
			case "lookup":
				if i+1 < len(fields) {
					lookup = fields[i+1]
				}
			}
		}
		if fwmark != hexMark && fwmark != decMark {
			continue
		}
		if lookup == table {
			return true
		}
	}
	return false
}

// defaultRoutePresent reports whether `ip route show table X` holds a default
// route, which is the only thing the dedicated table is supposed to contain.
func defaultRoutePresent(out string) bool {
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "default ") {
			return true
		}
	}
	return false
}
