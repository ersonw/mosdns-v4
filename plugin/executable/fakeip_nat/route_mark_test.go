package fakeipnat

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

// newMarkPlugin builds a plugin whose data path is configured for destination
// marking, with a fake runner behind it. The aggregation loop that Init started
// is stopped first: the tests below assert what startRouteAggregation does with
// mark routing active, and a loop already holding the handles would hide that.
func newMarkPlugin(t *testing.T, runner *fakeRunner) *FakeIPNatPlugin {
	t.Helper()
	p := newNativePlugin(t, runner, nil)
	p.stopRouteAggregation()
	p.routeMark = 256
	p.routeRulePriority = 1000
	p.routeTable = "oversea"
	return p
}

// TestMarkRoutingInstallsSetChainsAndRule checks the whole installation: the
// set that names the destinations, both mark chains, the two mark rules,
// the default route of the dedicated table and the policy rule that points
// marked packets at it.
func TestMarkRoutingInstallsSetChainsAndRule(t *testing.T) {
	runner := &fakeRunner{}
	p := newMarkPlugin(t, runner)
	p.nextHop = "10.9.8.7"
	p.nextHopDev = "eth1"

	if err := p.setupMarkRouting(context.Background()); err != nil {
		t.Fatalf("setupMarkRouting failed: %v", err)
	}
	if !p.markActiveNow() {
		t.Fatalf("mark routing reported inactive after a successful setup")
	}

	want := []string{
		"nft add set ip fakeip_test real_ipv4",
		"nft add chain ip fakeip_test mark_prerouting",
		"nft add rule ip fakeip_test mark_prerouting ip daddr @real_ipv4 ip saddr != 198.18.0.0/16 meta mark set 256",
		"nft add chain ip fakeip_test mark_output",
		"nft add rule ip fakeip_test mark_output ip daddr @real_ipv4 ip saddr != 198.18.0.0/16 meta mark set 256",
		"ip route replace default via 10.9.8.7 dev eth1 table oversea",
		"ip rule add fwmark 256 lookup oversea prio 1000",
	}
	for _, substr := range want {
		if _, ok := runner.find(substr); !ok {
			t.Fatalf("missing command %q in:\n%s", substr, strings.Join(runner.all(), "\n"))
		}
	}

	// A second setup in the same process must not duplicate the nft objects: only
	// the route refresh and the rule re-add are left to do.
	before := len(runner.all())
	if err := p.setupMarkRouting(context.Background()); err != nil {
		t.Fatalf("second setupMarkRouting failed: %v", err)
	}
	second := runner.all()[before:]
	if len(second) != 3 {
		t.Fatalf("second setup ran %d commands, want the route refresh and the rule re-add:\n%s",
			len(second), strings.Join(second, "\n"))
	}
	for _, call := range second {
		if strings.HasPrefix(call, "nft ") {
			t.Fatalf("second setup recreated an nft object: %q", call)
		}
	}
}

// TestMarkRoutingUsesSystemDefaultRouteWithoutHop covers the deployment where
// next_hop and next_hop_dev are empty: the dedicated table has to be steered
// somewhere, so the system default route is the only sane source.
func TestMarkRoutingUsesSystemDefaultRouteWithoutHop(t *testing.T) {
	runner := &fakeRunner{}
	p := newMarkPlugin(t, runner)
	p.nextHop = ""
	p.nextHopDev = ""

	if err := p.setupMarkRouting(context.Background()); err != nil {
		t.Fatalf("setupMarkRouting failed: %v", err)
	}
	call, ok := runner.find("ip route replace default")
	if !ok {
		t.Fatalf("no default route written:\n%s", strings.Join(runner.all(), "\n"))
	}
	if call != "ip route replace default via 10.0.0.1 dev eth0 table oversea" {
		t.Fatalf("default route = %q, want the system default via 10.0.0.1 dev eth0", call)
	}
	if _, ok := runner.find("ip rule add fwmark 256 lookup oversea prio 1000"); !ok {
		t.Fatalf("no policy rule written:\n%s", strings.Join(runner.all(), "\n"))
	}
}

// TestMarkRealIPOnlyEntersTheSet is the point of the whole change: a resolved
// address must not produce a host route once mark routing is up.
func TestMarkRealIPOnlyEntersTheSet(t *testing.T) {
	runner := &fakeRunner{}
	p := newMarkPlugin(t, runner)
	p.nextHop = "10.9.8.7"
	p.nextHopDev = "eth1"
	if err := p.setupMarkRouting(context.Background()); err != nil {
		t.Fatalf("setupMarkRouting failed: %v", err)
	}

	before := len(runner.all())
	p.applyHostRoute(context.Background(), "203.0.113.9", "10.9.8.7", "eth1")

	added := runner.all()
	if len(added) != before+1 {
		t.Fatalf("applyHostRoute ran %d commands, want exactly the set element:\n%s",
			len(added)-before, strings.Join(added[before:], "\n"))
	}
	if last := added[len(added)-1]; last != "nft add element ip fakeip_test real_ipv4 { 203.0.113.9 }" {
		t.Fatalf("last command = %q, want the set element", last)
	}
	if _, ok := runner.find("ip route replace 203.0.113.9/32"); ok {
		t.Fatalf("a host route was written while mark routing is active:\n%s", strings.Join(added, "\n"))
	}
}

// TestMarkRealIPFailureFallsBackToHostRoute keeps the data path working when
// the set write fails: the plugin degrades to the old shape instead of
// black-holing the address.
func TestMarkRealIPFailureFallsBackToHostRoute(t *testing.T) {
	runner := &fakeRunner{failContains: "nft add element"}
	p := newMarkPlugin(t, runner)
	p.nextHop = "10.9.8.7"
	p.nextHopDev = "eth1"

	// The set itself cannot be filled, so install the routing part only; the
	// nft objects are irrelevant to what this test asserts.
	p.markMu.Lock()
	p.markActive = true
	p.markMu.Unlock()

	p.applyHostRoute(context.Background(), "203.0.113.10", "10.9.8.7", "eth1")

	// The route command differs per platform (ip route replace on linux, route
	// add on the BSDs), so the check is on the address and on it not being the
	// set write that just failed.
	fellBack := false
	for _, call := range runner.all() {
		if strings.Contains(call, "203.0.113.10") && !strings.HasPrefix(call, "nft add element") {
			fellBack = true
		}
	}
	if !fellBack {
		t.Fatalf("no fallback host route written:\n%s", strings.Join(runner.all(), "\n"))
	}
}

// TestCleanupMarkRoutingRemovesRuleAndRoute removes the two fixed objects the
// installation wrote. Leaving either behind would keep steering traffic into a
// table that is about to be flushed.
func TestCleanupMarkRoutingRemovesRuleAndRoute(t *testing.T) {
	runner := &fakeRunner{}
	p := newMarkPlugin(t, runner)
	p.nextHop = "10.9.8.7"
	p.nextHopDev = "eth1"
	if err := p.setupMarkRouting(context.Background()); err != nil {
		t.Fatalf("setupMarkRouting failed: %v", err)
	}

	before := len(runner.all())
	p.cleanupMarkRouting(context.Background())

	cleaned := runner.all()[before:]
	if len(cleaned) != 2 {
		t.Fatalf("cleanup ran %d commands, want the rule delete and the route delete:\n%s",
			len(cleaned), strings.Join(cleaned, "\n"))
	}
	if cleaned[0] != "ip rule del fwmark 256 lookup oversea prio 1000" {
		t.Fatalf("first cleanup command = %q, want the policy rule delete", cleaned[0])
	}
	if cleaned[1] != "ip route del default table oversea" {
		t.Fatalf("second cleanup command = %q, want the default route delete", cleaned[1])
	}
	if p.markActiveNow() {
		t.Fatalf("mark routing still reported active after cleanup")
	}
	p.markMu.Lock()
	ready := p.markReady
	p.markMu.Unlock()
	if ready {
		t.Fatalf("the nft objects were still reported ready after cleanup, the next setup would skip them")
	}
}

// TestMarkModeSkipsRouteAggregation checks the loop: under mark routing the
// mapped addresses never reach a routing table, so a scan would only churn.
func TestMarkModeSkipsRouteAggregation(t *testing.T) {
	runner := &fakeRunner{}
	p := newMarkPlugin(t, runner)
	if err := p.setupMarkRouting(context.Background()); err != nil {
		t.Fatalf("setupMarkRouting failed: %v", err)
	}

	p.startRouteAggregation()

	p.aggMu.Lock()
	started := p.aggStop != nil
	p.aggMu.Unlock()
	if started {
		t.Fatalf("aggregation loop started while mark routing is active")
	}
	if _, ok := runner.find("ip -4 route show"); ok {
		t.Fatalf("aggregation scanned the routing table:\n%s", strings.Join(runner.all(), "\n"))
	}
}

// scriptRunner answers the read-only probes of the startup self-check from a
// table of prefixes; anything it does not know fails the way a missing object
// does. It exists so the check can be exercised without a kernel.
type scriptRunner struct {
	answers map[string]string
	calls   []string
}

func (s *scriptRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	call := name + " " + strings.Join(args, " ")
	s.calls = append(s.calls, call)
	for prefix, out := range s.answers {
		if strings.HasPrefix(call, prefix) {
			return out, nil
		}
	}
	return "", fmt.Errorf("fake failure: %s", call)
}

const markTableJSON = `{"nftables":[{"metainfo":{"version":"1.0.9"}},` +
	`{"table":{"family":"ip","name":"fakeip_test"}},` +
	`{"set":{"family":"ip","name":"real_ipv4","table":"fakeip_test","type":"ipv4_addr",` +
	`"elem":[{"val":"23.33.184.230"},{"val":"57.145.12.1"}]}},` +
	`{"chain":{"family":"ip","name":"mark_prerouting"}},` +
	`{"chain":{"family":"ip","name":"mark_output"}}]}`

// TestVerifyMarkRoutingReadsBackTheWholePath checks that a complete installation
// is reported as complete, including the set size and both chain names.
func TestVerifyMarkRoutingReadsBackTheWholePath(t *testing.T) {
	runner := &scriptRunner{answers: map[string]string{
		"nft -j list table ip fakeip_test": markTableJSON,
		"ip rule show":                     "10:\tfrom all fwmark 0xa lookup Oversea_Traffic_Table\n1000:\tfrom all fwmark 0x100 lookup oversea",
		"ip route show table oversea":      "default via 10.9.8.7 dev eth1",
	}}
	p := newNativePlugin(t, runner, nil)
	p.routeMark = 256
	p.routeTable = "oversea"

	check := p.verifyMarkRouting(context.Background())
	if !check.SetExists || check.SetSize != 2 {
		t.Fatalf("set: exists=%v size=%d, want exists=true size=2", check.SetExists, check.SetSize)
	}
	if !check.Chains[markPreroutingChain] || !check.Chains[markOutputChain] {
		t.Fatalf("chains = %v, want both mark chains", check.Chains)
	}
	if !check.RuleExists {
		t.Fatalf("the fwmark 0x100 lookup oversea rule was not recognised")
	}
	if !check.DefaultRoute {
		t.Fatalf("the default route of the dedicated table was not recognised")
	}
}

// TestVerifyMarkRoutingReportsMissingObjects checks the case the self-check
// exists for: installation silently did not take effect.
func TestVerifyMarkRoutingReportsMissingObjects(t *testing.T) {
	runner := &scriptRunner{answers: map[string]string{
		// A table without the mark set and without the mark chains.
		"nft -j list table ip fakeip_test": `{"nftables":[{"table":{"family":"ip","name":"fakeip_test"}}]}`,
		// Only somebody else's rules are present.
		"ip rule show":                "10:\tfrom all fwmark 0xa lookup Oversea_Traffic_Table",
		"ip route show table oversea": "",
	}}
	p := newNativePlugin(t, runner, nil)
	p.routeMark = 256
	p.routeTable = "oversea"

	check := p.verifyMarkRouting(context.Background())
	if check.SetExists || check.SetSize != 0 {
		t.Fatalf("set: exists=%v size=%d, want exists=false size=0", check.SetExists, check.SetSize)
	}
	if len(check.Chains) != 0 {
		t.Fatalf("chains = %v, want none", check.Chains)
	}
	if check.RuleExists {
		t.Fatalf("a rule with mark 0xa must not satisfy mark 0x100")
	}
	if check.DefaultRoute {
		t.Fatalf("an empty table must not report a default route")
	}
}

// TestVerifyMarkRoutingTreatsNftErrorsAsAbsent checks that a missing table or a
// non-JSON answer counts as "not installed" instead of panicking.
func TestVerifyMarkRoutingTreatsNftErrorsAsAbsent(t *testing.T) {
	p := newNativePlugin(t, &scriptRunner{}, nil) // every command fails
	p.routeMark = 256
	p.routeTable = "oversea"

	check := p.verifyMarkRouting(context.Background())
	if check.SetExists || check.RuleExists || check.DefaultRoute {
		t.Fatalf("check = %+v, want every object absent", check)
	}
}

// TestMarkRulePresentMatchesKernelSpellings covers the shapes `ip rule show`
// can print: hex, decimal, a masked mark and a named table.
func TestMarkRulePresentMatchesKernelSpellings(t *testing.T) {
	cases := []struct {
		name string
		out  string
		want bool
	}{
		{"hex mark", "1000:\tfrom all fwmark 0x100 lookup 1001", true},
		{"decimal mark", "1000:\tfrom all fwmark 256 lookup 1001", true},
		{"masked mark", "1000:\tfrom all fwmark 0x100/0xffffffff lookup 1001", true},
		{"named table", "1000:\tfrom all fwmark 0x100 lookup oversea", true},
		{"other mark", "10:\tfrom all fwmark 0xa lookup 1001", false},
		{"other table", "1000:\tfrom all fwmark 0x100 lookup Oversea_Traffic_Table", false},
		{"empty", "", false},
	}
	for _, c := range cases {
		table := "1001"
		if c.name == "named table" {
			table = "oversea"
		}
		if got := markRulePresent(c.out, 256, table); got != c.want {
			t.Fatalf("%s: markRulePresent = %v, want %v", c.name, got, c.want)
		}
	}
}

// TestDefaultRoutePresent checks that only a default route counts, not the
// per-address entries the old shape wrote.
func TestDefaultRoutePresent(t *testing.T) {
	if !defaultRoutePresent("default via 10.9.8.7 dev eth1") {
		t.Fatalf("a plain default route was not recognised")
	}
	if defaultRoutePresent("23.33.184.230 via 10.9.8.7 dev eth1") {
		t.Fatalf("a host route must not count as a default route")
	}
	if defaultRoutePresent("") {
		t.Fatalf("an empty table must not report a default route")
	}
}

// TestMarkRoutingSkipsTunModeWithoutRealIP pins the remaining limit: fakeip +
// tun already enters the device as a whole range, so a mark would only steer
// the stack's own dials back into it. Neither setup nor cleanup touches the
// kernel in that shape.
func TestMarkRoutingSkipsTunModeWithoutRealIP(t *testing.T) {
	runner := &fakeRunner{}
	p := newMarkPlugin(t, runner)
	p.useTun = true

	if p.markRoutingEnabled() {
		t.Fatalf("mark routing must stay disabled with fakeip in tun mode")
	}
	p.cleanupMarkRouting(context.Background())
	if calls := runner.all(); len(calls) != 0 {
		t.Fatalf("cleanup in tun mode issued commands: %v", calls)
	}
}

// TestMarkRoutingInTunModePointsTheTableAtTheDevice covers the realip + tun
// shape: the marked destinations are routed into the device the plugin owns,
// not at a next hop, because the device is what carries them (through the
// proxy, or the outlet route when there is none).
func TestMarkRoutingInTunModePointsTheTableAtTheDevice(t *testing.T) {
	runner := &fakeRunner{}
	p := newMarkPlugin(t, runner)
	p.useTun = true
	p.realIP = true
	p.tunDev = "mth0"
	p.nextHop = "10.9.8.7"
	p.nextHopDev = "eth1"

	if !p.markRoutingEnabled() {
		t.Fatalf("mark routing must be enabled for realip in tun mode")
	}
	if err := p.setupMarkRouting(context.Background()); err != nil {
		t.Fatalf("setupMarkRouting failed: %v", err)
	}
	if _, ok := runner.find("ip route replace default dev mth0 table oversea"); !ok {
		t.Fatalf("marked traffic was not pointed at the device:\n%s", strings.Join(runner.all(), "\n"))
	}
	if _, ok := runner.find("via 10.9.8.7"); ok {
		t.Fatalf("tun mode must not route marked traffic at the next hop:\n%s", strings.Join(runner.all(), "\n"))
	}
}

// TestHostRouteTableKeepsTheDedicatedTableFree pins the split of responsibilities:
// route_table belongs to the mark path, and every per-address route (the
// fallback after a failed set write, the aggregation scan, the ledger row) goes
// to main instead. Writing such a route into the dedicated table would strand it,
// because only packets that already carry the mark ever look there.
func TestHostRouteTableKeepsTheDedicatedTableFree(t *testing.T) {
	p := newMarkPlugin(t, &fakeRunner{})
	if got := p.hostRouteTable(); got != "main" {
		t.Fatalf("host route table with marking enabled = %q, want main", got)
	}

	p.routeMark = 0
	if got := p.hostRouteTable(); got != "oversea" {
		t.Fatalf("host route table without marking = %q, want the configured oversea", got)
	}
}

// TestMarkedFallbackRouteIsRecordedInMain checks the whole fallback: the set
// write fails, the host route is written with main, and the ledger records main
// so cleanup deletes it from the table it was actually written into.
func TestMarkedFallbackRouteIsRecordedInMain(t *testing.T) {
	runner := &fakeRunner{failContains: "nft add element"}
	p := newMarkPlugin(t, runner)
	p.nextHop = "10.9.8.7"
	p.nextHopDev = "eth1"
	p.markMu.Lock()
	p.markActive = true // installed earlier; only the set write fails here
	p.markMu.Unlock()

	p.applyHostRoute(context.Background(), "203.0.113.10", "10.9.8.7", "eth1")

	routes, err := p.ledgerRoutes(context.Background())
	if err != nil {
		t.Fatalf("read ledger failed: %v", err)
	}
	if len(routes) != 1 {
		t.Fatalf("ledger rows = %d, want the one fallback route", len(routes))
	}
	if routes[0].routeTable != "main" {
		t.Fatalf("fallback route recorded in table %q, want main", routes[0].routeTable)
	}
}
