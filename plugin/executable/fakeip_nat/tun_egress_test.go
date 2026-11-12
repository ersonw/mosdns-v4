package fakeipnat

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ersonw/mosdns-v4/coremain"
	"go.uber.org/zap"
)

func TestTunRoutePlan(t *testing.T) {
	plan := tunRoutePlan("198.18.0.0/15", "192.168.1.1", "en0", "100", "")
	if len(plan) != 4 {
		t.Fatalf("plan has %d steps, want 4", len(plan))
	}
	want := "ip route replace default via 192.168.1.1 dev en0 table 100"
	if got := strings.Join(plan[0], " "); got != want {
		t.Fatalf("route step = %q, want %q", got, want)
	}
	if got := strings.Join(plan[1], " "); got != "ip rule del from 198.18.0.0/15 lookup 100" {
		t.Fatalf("stale rule delete step = %q", got)
	}
	if got := strings.Join(plan[2], " "); got != "ip rule del from 198.18.0.0/15 to ! 198.18.0.0/15 lookup 100" {
		t.Fatalf("rule delete step = %q", got)
	}
	if got := strings.Join(plan[3], " "); got != "ip rule add from 198.18.0.0/15 to ! 198.18.0.0/15 lookup 100" {
		t.Fatalf("rule add step = %q", got)
	}

	// Without a device the gateway alone still describes the table.
	plan = tunRoutePlan("198.18.0.0/15", "192.168.1.1", "", "100", "")
	if got := strings.Join(plan[0], " "); got != "ip route replace default via 192.168.1.1 table 100" {
		t.Fatalf("gateway-only route = %q", got)
	}

	// Without a gateway the device alone carries the default route.
	plan = tunRoutePlan("198.18.0.0/15", "", "en0", "100", "")
	if got := strings.Join(plan[0], " "); got != "ip route replace default dev en0 table 100" {
		t.Fatalf("device-only route = %q", got)
	}

	// With mark routing the outlet rule carries an explicit priority so it is
	// consulted before the mark rule instead of landing behind it.
	plan = tunRoutePlan("198.18.0.0/15", "192.168.1.1", "en0", "100", "999")
	if got := strings.Join(plan[3], " "); got != "ip rule add from 198.18.0.0/15 to ! 198.18.0.0/15 lookup 100 prio 999" {
		t.Fatalf("prioritized rule add step = %q", got)
	}

	// Neither one: nothing can be installed.
	if plan := tunRoutePlan("198.18.0.0/15", "", "", "100", ""); plan != nil {
		t.Fatalf("plan without gateway or device = %v, want nil", plan)
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
