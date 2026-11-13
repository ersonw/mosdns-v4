package fakeipnat

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ersonw/mosdns-v4/coremain"
	"go.uber.org/zap"
)

// ipCmd renders one step of a plan the way the runner receives it: the "ip"
// binary plus its arguments.
func ipCmd(args []string) string {
	return "ip " + strings.Join(args, " ")
}

func TestTunRoutePlan(t *testing.T) {
	plan := tunRoutePlan("198.18.0.1/32", "192.168.1.1", "en0", "100", "")
	if plan == nil {
		t.Fatalf("plan is nil although a gateway and a device are known")
	}
	want := "ip route replace default via 192.168.1.1 dev en0 table 100"
	if got := ipCmd(plan.route); got != want {
		t.Fatalf("route step = %q, want %q", got, want)
	}
	if got := ipCmd(plan.delRule); got != "ip rule del from 198.18.0.1/32 lookup 100" {
		t.Fatalf("stale rule delete step = %q", got)
	}
	if got := ipCmd(plan.addRule); got != "ip rule add from 198.18.0.1/32 lookup 100" {
		t.Fatalf("rule add step = %q", got)
	}
	// "ip rule add from X to !X" is rejected by iproute2 ("any valid prefix is
	// expected rather than \"!\"") and must never come back. The exclusion it
	// expressed is carried by the fake range rule at priority 5 instead.
	for _, step := range [][]string{plan.delRule, plan.addRule} {
		if joined := strings.Join(step, " "); strings.Contains(joined, "!") {
			t.Fatalf("rule step carries the unsupported \"!\" token: %q", joined)
		}
	}

	// Without a device the gateway alone still describes the table.
	plan = tunRoutePlan("198.18.0.1/32", "192.168.1.1", "", "100", "")
	if got := ipCmd(plan.route); got != "ip route replace default via 192.168.1.1 table 100" {
		t.Fatalf("gateway-only route = %q", got)
	}

	// Without a gateway the device alone carries the default route.
	plan = tunRoutePlan("198.18.0.1/32", "", "en0", "100", "")
	if got := ipCmd(plan.route); got != "ip route replace default dev en0 table 100" {
		t.Fatalf("device-only route = %q", got)
	}

	// With mark routing the outlet rule carries an explicit priority so it is
	// consulted before the mark rule instead of landing behind it. The delete
	// stays wider than the add, so a stale rule with another priority goes too.
	plan = tunRoutePlan("198.18.0.1/32", "192.168.1.1", "en0", "100", "999")
	if got := ipCmd(plan.addRule); got != "ip rule add from 198.18.0.1/32 lookup 100 prio 999" {
		t.Fatalf("prioritized rule add step = %q", got)
	}
	if got := ipCmd(plan.delRule); got != "ip rule del from 198.18.0.1/32 lookup 100" {
		t.Fatalf("delete must not pin a priority, got %q", got)
	}

	// Neither one: nothing can be installed.
	if plan := tunRoutePlan("198.18.0.1/32", "", "", "100", ""); plan != nil {
		t.Fatalf("plan without gateway or device = %v, want nil", plan)
	}
}

// TestTunEgressSourceIsOneHost guards the rule's width. A rule matching the
// whole range also matches everything the stack sends back to a client (its
// source is the fake address the client dialled), and those SYN-ACKs and echo
// replies then leave through the outlet table instead of reaching the client -
// the state that made every connection time out on ph-vpn.
func TestTunEgressSourceIsOneHost(t *testing.T) {
	p := newNativePlugin(t, &fakeRunner{}, func(context.Context, string) bool { return true })

	source := p.tunEgressSource()
	if source != "198.18.0.1/32" {
		t.Fatalf("outlet source = %q, want the range head as a /32", source)
	}
	plan := tunRoutePlan(source, "192.168.1.1", "eth0", "101", "")
	if plan == nil {
		t.Fatalf("plan is nil")
	}
	for _, step := range [][]string{plan.delRule, plan.addRule} {
		if joined := strings.Join(step, " "); strings.Contains(joined, p.cidr) {
			t.Fatalf("outlet rule still matches the whole range: %q", joined)
		}
	}

	// The same address has to be derivable from the configured range alone, so
	// the cleanup of a previous run can name it without the plugin instance.
	if got := tunEgressSourceOf("198.18.0.0/16"); got != "198.18.0.1/32" {
		t.Fatalf("source of 198.18.0.0/16 = %q", got)
	}
	if got := tunEgressSourceOf("198.19.0.0/16"); got != "198.19.0.1/32" {
		t.Fatalf("source of 198.19.0.0/16 = %q", got)
	}
}

// TestTunEgressPlanRunsTheAdd is the regression for the positional plan: the
// installer used to run the second delete where the add was meant, so no outlet
// rule was ever installed while the log blamed an "add ip rule failed".
func TestTunEgressPlanRunsTheAdd(t *testing.T) {
	runner := &fakeRunner{}
	p := newNativePlugin(t, runner, func(context.Context, string) bool { return true })

	plan := tunRoutePlan(p.tunEgressSource(), "192.168.1.1", "eth0", "101", "999")
	if plan == nil {
		t.Fatalf("plan is nil")
	}
	plan.staleRule = egressRuleArgs("del", p.cidr, "101", "")
	if _, err := p.applyTunEgressPlan(context.Background(), plan); err != nil {
		t.Fatalf("apply plan: %v", err)
	}

	calls := runner.all()
	joined := strings.Join(calls, "\n")
	want := "ip rule add from " + p.tunEgressSource() + " lookup 101 prio 999"
	if !strings.Contains(joined, want) {
		t.Fatalf("the add never ran, want %q in:\n%s", want, joined)
	}
	// Order matters: the route has to exist before the rule can point at it,
	// and the stale rule is dropped before the new one is added.
	index := func(substr string) int {
		for i, call := range calls {
			if strings.Contains(call, substr) {
				return i
			}
		}
		return -1
	}
	routeAt := index("ip route replace default")
	staleAt := index("ip rule del from " + p.cidr)
	addAt := index(want)
	if routeAt < 0 || staleAt < 0 || addAt < 0 {
		t.Fatalf("missing step in:\n%s", joined)
	}
	if !(routeAt < staleAt && staleAt < addAt) {
		t.Fatalf("steps out of order (route=%d del=%d add=%d):\n%s", routeAt, staleAt, addAt, joined)
	}
}

// retryRunner fails the first route replaces, then behaves like a healthy
// runner: the shape of a machine whose default route is not ready yet.
type retryRunner struct {
	fakeRunner
	failFirst int
	routes    int
}

func (r *retryRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	call := name + " " + strings.Join(args, " ")
	if strings.HasPrefix(call, "ip route replace") {
		r.routes++
		if r.routes <= r.failFirst {
			return "", fmt.Errorf("network is unreachable")
		}
	}
	return r.fakeRunner.Run(ctx, name, args...)
}

// TestTunEgressPlanRetriesTheRoute: the outlet is installed during boot, before
// the kernel necessarily has a default route. A failed route must be retried a
// bounded number of times instead of leaving the range on the host table for the
// rest of the process lifetime.
func TestTunEgressPlanRetriesTheRoute(t *testing.T) {
	oldDelay := tunEgressRetryDelay
	tunEgressRetryDelay = time.Millisecond
	defer func() { tunEgressRetryDelay = oldDelay }()

	runner := &retryRunner{failFirst: 2}
	p := newNativePlugin(t, runner, func(context.Context, string) bool { return true })

	plan := tunRoutePlan(p.cidr, "192.168.1.1", "eth0", "103", "999")
	if plan == nil {
		t.Fatalf("plan is nil")
	}
	step, err := p.applyTunEgressPlan(context.Background(), plan)
	if err != nil {
		t.Fatalf("the retry did not recover: step=%q err=%v", step, err)
	}
	if runner.routes != 3 {
		t.Fatalf("route replace attempts = %d, want 3", runner.routes)
	}
	// The rule must only be added once the route finally succeeded.
	calls := runner.all()
	joined := strings.Join(calls, "\n")
	if !strings.Contains(joined, "ip rule add from "+p.cidr+" lookup 103 prio 999") {
		t.Fatalf("the add never ran after the retry:\n%s", joined)
	}
}

// TestTunEgressPlanStopsRetryingWhenTheContextEnds: a shutdown during the backoff
// must not hold the process for the remaining attempts.
func TestTunEgressPlanStopsRetryingWhenTheContextEnds(t *testing.T) {
	oldDelay := tunEgressRetryDelay
	tunEgressRetryDelay = time.Second
	defer func() { tunEgressRetryDelay = oldDelay }()

	runner := &fakeRunner{failContains: "route replace"}
	p := newNativePlugin(t, runner, func(context.Context, string) bool { return true })

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	plan := tunRoutePlan(p.cidr, "192.168.1.1", "eth0", "104", "")
	if plan == nil {
		t.Fatalf("plan is nil")
	}
	start := time.Now()
	step, err := p.applyTunEgressPlan(ctx, plan)
	if err == nil {
		t.Fatalf("a failing route must be reported")
	}
	if step != "route" {
		t.Fatalf("failed step = %q, want \"route\"", step)
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("retries ignored the context and waited %v", elapsed)
	}
}

// TestTunEgressPlanRollsBackTheRouteOnRuleFailure: a rule that cannot be added
// has to take the default route with it, otherwise the table keeps a default
// route that no rule points at — the state that made the outlet look installed.
func TestTunEgressPlanRollsBackTheRouteOnRuleFailure(t *testing.T) {
	oldDelay := tunEgressRetryDelay
	tunEgressRetryDelay = time.Millisecond
	defer func() { tunEgressRetryDelay = oldDelay }()

	runner := &fakeRunner{failContains: "rule add"}
	p := newNativePlugin(t, runner, func(context.Context, string) bool { return true })

	plan := tunRoutePlan(p.cidr, "192.168.1.1", "eth0", "102", "")
	if plan == nil {
		t.Fatalf("plan is nil")
	}
	step, err := p.applyTunEgressPlan(context.Background(), plan)
	if err == nil {
		t.Fatalf("a failing rule add must be reported")
	}
	if step != "rule" {
		t.Fatalf("failed step = %q, want \"rule\"", step)
	}
	calls := strings.Join(runner.all(), "\n")
	if !strings.Contains(calls, "ip route del default table 102") {
		t.Fatalf("the default route was left behind:\n%s", calls)
	}
}

func newRouteTestPlugin(t *testing.T, extra *Args) *FakeIPNatPlugin {
	t.Helper()
	args := &Args{
		DBPath:      filepath.Join(t.TempDir(), "fakeip.db"),
		TablePrefix: "tunroute",
		IPv4Range:   "198.18.0.0/16",
		UseTun:      true,
	}
	if extra != nil {
		*args = *extra
		args.DBPath = filepath.Join(t.TempDir(), "fakeip.db")
	}
	bp := coremain.NewBP("test_tun_egress", PluginType, zap.NewNop(), nil)
	plugin, err := Init(bp, args)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	fp := plugin.(*FakeIPNatPlugin)
	t.Cleanup(func() { _ = fp.Close() })
	return fp
}

func TestTunRouteTableDefault(t *testing.T) {
	fp := newRouteTestPlugin(t, nil)
	if fp.tunRouteTable != "100" {
		t.Fatalf("tunRouteTable = %q, want 100", fp.tunRouteTable)
	}
}

func TestTunRouteTableRejectsBadName(t *testing.T) {
	bp := coremain.NewBP("test_tun_egress", PluginType, zap.NewNop(), nil)
	_, err := Init(bp, &Args{
		DBPath:        filepath.Join(t.TempDir(), "fakeip.db"),
		TablePrefix:   "tunroute",
		IPv4Range:     "198.18.0.0/16",
		UseTun:        true,
		TunRouteTable: "bad name!",
	})
	if err == nil {
		t.Fatalf("an invalid tun_route_table must be rejected")
	}
}

func TestParseIPRouteDefault(t *testing.T) {
	hop, dev := parseIPRouteDefault("default via 192.168.1.1 dev eth0 proto dhcp metric 100\n")
	if hop != "192.168.1.1" || dev != "eth0" {
		t.Fatalf("got hop=%q dev=%q", hop, dev)
	}
	hop, dev = parseIPRouteDefault("")
	if hop != "" || dev != "" {
		t.Fatalf("empty output must stay empty, got hop=%q dev=%q", hop, dev)
	}
}

func TestParseBSDDefaultRoute(t *testing.T) {
	out := "   route to: default\ndestination: default\n      gateway: 192.168.88.1\n  interface: en0\n      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>\n"
	hop, dev := parseBSDDefaultRoute(out)
	if hop != "192.168.88.1" || dev != "en0" {
		t.Fatalf("got hop=%q dev=%q", hop, dev)
	}
}

// TestFakeRangeRulePinsTheRangeToMain: a gateway with its own policy routing
// (VyOS marks every non-CN destination into an oversea table at priority 10)
// intercepts fake destinations before main is consulted. The plugin has to
// install its own rule ahead of that policy, keyed on the configured range.
func TestFakeRangeRulePinsTheRangeToMain(t *testing.T) {
	runner := &fakeRunner{}
	p := newNativePlugin(t, runner, func(context.Context, string) bool { return true })
	p.policyRuleSupported = true

	if _, ok := p.installFakeRangeRule(context.Background()); !ok {
		t.Fatalf("fake range rule was not installed")
	}

	calls := strings.Join(runner.all(), "\n")
	for _, want := range []string{
		"ip rule del to 198.18.0.0/16 lookup main prio 5",
		"ip rule add to 198.18.0.0/16 lookup main prio 5",
	} {
		if !strings.Contains(calls, want) {
			t.Fatalf("missing %q in:\n%s", want, calls)
		}
	}
}

// TestFakeRangeRuleIsInstalledWithAProxy: the proxy only changes the outlet of
// the stack's own dials. Packets addressed to a fake ip still have to enter the
// device, so the rule must exist even when the proxy carries the outlet.
func TestFakeRangeRuleIsInstalledWithAProxy(t *testing.T) {
	runner := &fakeRunner{}
	p := newNativePlugin(t, runner, func(context.Context, string) bool { return true })
	p.policyRuleSupported = true
	p.proxyActive = true

	p.setupTunEgress()

	calls := strings.Join(runner.all(), "\n")
	if !strings.Contains(calls, "ip rule add to 198.18.0.0/16 lookup main prio 5") {
		t.Fatalf("proxy branch skipped the fake range rule:\n%s", calls)
	}
	if strings.Contains(calls, "route replace default") {
		t.Fatalf("proxy branch installed an outlet route:\n%s", calls)
	}
}

// TestFakeRangeRuleCleanupRemovesTheSameSpec: cleanup deletes by the exact spec
// it added, so a restart cannot accumulate one rule per run.
func TestFakeRangeRuleCleanupRemovesTheSameSpec(t *testing.T) {
	runner := &fakeRunner{}
	p := newNativePlugin(t, runner, func(context.Context, string) bool { return true })
	p.policyRuleSupported = true

	cleanup, ok := p.installFakeRangeRule(context.Background())
	if !ok {
		t.Fatalf("fake range rule was not installed")
	}
	before := len(runner.all())
	cleanup()
	after := runner.all()
	if len(after) != before+1 || after[before] != "ip rule del to 198.18.0.0/16 lookup main prio 5" {
		t.Fatalf("cleanup did not delete the same spec:\n%s", strings.Join(after, "\n"))
	}
}

// TestFakeRangeRuleIsSkippedWithoutPolicyRules: a platform with no ip rule must
// not attempt to call it.
func TestFakeRangeRuleIsSkippedWithoutPolicyRules(t *testing.T) {
	runner := &fakeRunner{}
	p := newNativePlugin(t, runner, func(context.Context, string) bool { return true })
	p.policyRuleSupported = false

	if _, ok := p.installFakeRangeRule(context.Background()); ok {
		t.Fatalf("rule reported installed without platform support")
	}
	if calls := runner.all(); len(calls) != 0 {
		t.Fatalf("unsupported platform issued commands: %v", calls)
	}
}

// TestSweepRemovesTheRecordedFakeRuleWhenTheRangeChanges: the rule is found
// again only through its record, so an edited ipv4_range cannot leave the old
// range pinned in the ruleset.
func TestSweepRemovesTheRecordedFakeRuleWhenTheRangeChanges(t *testing.T) {
	runner := &fakeRunner{}
	p := newNativePlugin(t, runner, func(context.Context, string) bool { return true })
	p.policyRuleSupported = true
	ctx := context.Background()

	p.saveTunState(ctx, fakeRangeRuleState("198.18.0.0/15", 5), "")
	p.sweepRecordedTunState(ctx, fakeRangeRuleState(p.cidr, 5), "")

	calls := strings.Join(runner.all(), "\n")
	if !strings.Contains(calls, "ip rule del to 198.18.0.0/15 lookup main prio 5") {
		t.Fatalf("old range not removed:\n%s", calls)
	}
	fakeRule, _ := p.loadTunState(ctx)
	if fakeRule != fakeRangeRuleState(p.cidr, 5) {
		t.Fatalf("record not updated, got %q", fakeRule)
	}
}

// TestSweepRemovesTheRecordedOutletWhenTheTableChanges: tun_route_table edited
// from 100 to 101 must delete the rules and the default route in 100, not just
// install the new ones.
func TestSweepRemovesTheRecordedOutletWhenTheTableChanges(t *testing.T) {
	runner := &fakeRunner{}
	p := newNativePlugin(t, runner, func(context.Context, string) bool { return true })
	p.policyRuleSupported = true
	ctx := context.Background()

	p.saveTunState(ctx, "", tunEgressState("100", "198.18.0.0/15"))
	p.sweepRecordedTunState(ctx, "", tunEgressState("101", p.cidr))

	calls := strings.Join(runner.all(), "\n")
	for _, want := range []string{
		"ip rule del from 198.18.0.0/15 lookup 100",
		"ip route del default table 100",
	} {
		if !strings.Contains(calls, want) {
			t.Fatalf("missing %q in:\n%s", want, calls)
		}
	}
}

// TestNonTunStartupRemovesRecordedTunObjects: switching to the NAT data path has
// to clear what the previous tun run left, even though this run's configuration
// names none of it.
func TestNonTunStartupRemovesRecordedTunObjects(t *testing.T) {
	runner := &fakeRunner{}
	p := newNativePlugin(t, runner, func(context.Context, string) bool { return true })
	p.policyRuleSupported = true
	ctx := context.Background()

	p.saveTunState(ctx, fakeRangeRuleState("198.18.0.0/15", 5), tunEgressState("101", "198.18.0.0/15"))
	p.cleanupStaleTunEgress(ctx)

	calls := strings.Join(runner.all(), "\n")
	for _, want := range []string{
		"ip rule del to 198.18.0.0/15 lookup main prio 5",
		"ip route del default table 101",
	} {
		if !strings.Contains(calls, want) {
			t.Fatalf("missing %q in:\n%s", want, calls)
		}
	}
	if fakeRule, egress := p.loadTunState(ctx); fakeRule != "" || egress != "" {
		t.Fatalf("record not cleared: fake=%q egress=%q", fakeRule, egress)
	}
}

// TestStopTunEgressClearsTheRecord: stop removes the objects and forgets them in
// the same pass, so the next run has nothing to sweep.
func TestStopTunEgressClearsTheRecord(t *testing.T) {
	runner := &fakeRunner{}
	p := newNativePlugin(t, runner, func(context.Context, string) bool { return true })
	p.policyRuleSupported = true
	p.nextHop = "10.0.0.1"
	p.nextHopDev = "eth0"

	p.setupTunEgress()
	if fakeRule, egress := p.loadTunState(context.Background()); fakeRule == "" || egress == "" {
		t.Fatalf("setup did not record its objects: fake=%q egress=%q", fakeRule, egress)
	}

	p.stopTunEgress()
	if fakeRule, egress := p.loadTunState(context.Background()); fakeRule != "" || egress != "" {
		t.Fatalf("record not cleared on stop: fake=%q egress=%q", fakeRule, egress)
	}
}

// TestTunStateCodecRejectsUnusableSpecs keeps a corrupted row from turning into
// a command against the wrong range or the main table.
func TestTunStateCodecRejectsUnusableSpecs(t *testing.T) {
	if _, _, ok := parseFakeRangeRuleState(""); ok {
		t.Fatalf("empty fake rule state accepted")
	}
	if _, _, ok := parseFakeRangeRuleState("notanumber|198.18.0.0/15"); ok {
		t.Fatalf("non numeric priority accepted")
	}
	if _, _, ok := parseFakeRangeRuleState("0|198.18.0.0/15"); ok {
		t.Fatalf("priority 0 accepted")
	}
	if _, _, ok := parseTunEgressState("main|198.18.0.0/15"); ok {
		t.Fatalf("main table accepted as an outlet")
	}
	if _, _, ok := parseTunEgressState("101|"); ok {
		t.Fatalf("empty range accepted")
	}
	if got := tunEgressState("main", "198.18.0.0/15"); got != "" {
		t.Fatalf("main must encode as nothing, got %q", got)
	}
}
