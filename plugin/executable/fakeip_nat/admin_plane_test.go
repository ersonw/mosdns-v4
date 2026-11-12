package fakeipnat

import (
	"context"
	"strings"
	"testing"
)

// The plane view is what a shell session would read: the plugin's own fields
// next to the objects the kernel still answers for. A rule list that keeps only
// our lines is the part that stops VyOS rules from leaking into the reply.
func TestAdminPlaneReportsTheRunningPlane(t *testing.T) {
	runner := &fakeRunner{ruleShow: strings.Join([]string{
		"0:\tfrom all lookup local",
		"5:\tfrom all to 198.18.0.0/16 lookup main",
		"10:\tfrom all fwmark 0xa lookup Oversea_Traffic_Table",
		"1000:\tfrom all fwmark 0x100 lookup oversea",
		"32766:\tfrom all lookup main",
	}, "\n")}
	p := newMarkPlugin(t, runner)
	p.useTun = true
	p.tunDev = "mth0"
	p.policyRuleSupported = true

	plane, err := p.AdminPlane(context.Background())
	if err != nil {
		t.Fatalf("AdminPlane: %v", err)
	}
	if plane.DataPlane != "tun" || plane.Device != "mth0" {
		t.Fatalf("plane = %s/%s, want tun/mth0", plane.DataPlane, plane.Device)
	}
	if plane.Range != p.cidr {
		t.Fatalf("range = %s, want %s", plane.Range, p.cidr)
	}
	if !plane.MarkEnabled || plane.RouteMark != 256 || plane.RouteTable != "oversea" {
		t.Fatalf("mark view = %v/%d/%s", plane.MarkEnabled, plane.RouteMark, plane.RouteTable)
	}
	if len(plane.Rules) != 2 {
		t.Fatalf("rules = %v, want the fake range pin and the mark rule only", plane.Rules)
	}
}

func TestOwnRuleLinesIgnoresForeignRules(t *testing.T) {
	out := strings.Join([]string{
		"5:\tfrom all to 198.18.0.0/15 lookup main",
		"10:\tfrom all fwmark 0xa lookup Oversea_Traffic_Table",
		"1500:\tfrom 198.18.0.0/15 lookup 123",
		"32766:\tfrom all lookup main",
	}, "\n")
	lines := ownRuleLines(out, "198.18.0.0/15", "123", "101", 0x7b)
	want := []string{
		"5:\tfrom all to 198.18.0.0/15 lookup main",
		"1500:\tfrom 198.18.0.0/15 lookup 123",
	}
	if len(lines) != len(want) {
		t.Fatalf("lines = %v, want %v", lines, want)
	}
	for i := range want {
		if lines[i] != want[i] {
			t.Fatalf("lines[%d] = %q, want %q", i, lines[i], want[i])
		}
	}
}

// A sweep must not remove the objects the running configuration owns; only the
// recorded leftovers of an earlier configuration go away.
func TestAdminSweepKeepsTheOwnedObjects(t *testing.T) {
	runner := &fakeRunner{}
	p := newMarkPlugin(t, runner)
	p.useTun = true
	p.policyRuleSupported = true
	p.tunRouteTable = "101"
	p.proxyActive = false

	// A previous run used another range and another outlet table.
	p.saveTunState(context.Background(), fakeRangeRuleState("198.18.0.0/15", tunFakeRulePriority),
		tunEgressState("100", "198.18.0.0/15"))

	removed, err := p.AdminSweep(context.Background())
	if err != nil {
		t.Fatalf("AdminSweep: %v", err)
	}
	if len(removed) != 2 {
		t.Fatalf("removed = %v, want the fake rule and the outlet", removed)
	}
	fakeRule, egress := p.loadTunState(context.Background())
	if fakeRule != fakeRangeRuleState(p.cidr, tunFakeRulePriority) {
		t.Fatalf("fake rule = %q, want the current one", fakeRule)
	}
	if egress != tunEgressState("101", p.cidr) {
		t.Fatalf("egress = %q, want the current one", egress)
	}
}

// With the proxy carrying the answers the stack has no outlet route, so a
// recorded outlet from a direct run is stale and must go.
func TestAdminSweepDropsTheOutletWhenTheProxyCarriesIt(t *testing.T) {
	p := newMarkPlugin(t, &fakeRunner{})
	p.useTun = true
	p.policyRuleSupported = true
	p.tunRouteTable = "101"
	p.proxyActive = true
	p.saveTunState(context.Background(), "", tunEgressState("101", p.cidr))

	removed, err := p.AdminSweep(context.Background())
	if err != nil {
		t.Fatalf("AdminSweep: %v", err)
	}
	if len(removed) != 1 || !strings.Contains(removed[0], "outlet") {
		t.Fatalf("removed = %v, want the outlet only", removed)
	}
	// The fake range pin stays recorded: this run owns it even when the proxy
	// carries the answers. Only the outlet is stale.
	fakeRule, egress := p.loadTunState(context.Background())
	if fakeRule != fakeRangeRuleState(p.cidr, tunFakeRulePriority) || egress != "" {
		t.Fatalf("state = %q/%q, want the fake rule kept and no outlet", fakeRule, egress)
	}
}
