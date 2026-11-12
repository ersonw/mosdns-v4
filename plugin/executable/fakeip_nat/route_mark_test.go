package fakeipnat

import (
	"context"
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
		"nft add rule ip fakeip_test mark_prerouting ip daddr @real_ipv4 meta mark set 256",
		"nft add chain ip fakeip_test mark_output",
		"nft add rule ip fakeip_test mark_output ip daddr @real_ipv4 meta mark set 256",
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
