package fakeipnat

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"testing"
)

// TestMarkStateRoundTrip pins the record the next run relies on: it survives a
// restart in the database and disappears once the path is removed.
func TestMarkStateRoundTrip(t *testing.T) {
	p := newTestPlugin(t, "198.18.0.0/16")
	ctx := context.Background()

	if mark, table := p.loadMarkState(ctx); mark != 0 || table != "" {
		t.Fatalf("fresh database reported a recorded path: mark=%d table=%q", mark, table)
	}
	p.saveMarkState(ctx, 123, "1001")
	mark, table := p.loadMarkState(ctx)
	if mark != 123 || table != "1001" {
		t.Fatalf("loadMarkState = (%d, %q), want (123, \"1001\")", mark, table)
	}
	p.clearMarkState(ctx)
	if mark, table := p.loadMarkState(ctx); mark != 0 || table != "" {
		t.Fatalf("state survived clearMarkState: mark=%d table=%q", mark, table)
	}
}

// TestMarkStateIgnoresUnsafeRecords keeps the cleanup from touching anything it
// cannot prove is its own: a zero mark and the main table are never ours.
func TestMarkStateIgnoresUnsafeRecords(t *testing.T) {
	p := newTestPlugin(t, "198.18.0.0/16")
	ctx := context.Background()

	p.saveMarkState(ctx, 0, "1001")
	if mark, table := p.loadMarkState(ctx); mark != 0 || table != "" {
		t.Fatalf("a zero mark was accepted: mark=%d table=%q", mark, table)
	}
	p.saveMarkState(ctx, 123, "main")
	if mark, table := p.loadMarkState(ctx); mark != 0 || table != "" {
		t.Fatalf("the main table was accepted: mark=%d table=%q", mark, table)
	}
}

// TestRemoveStaleMarkPath pins the two commands that undo a previous run. The
// rule is matched without its priority: that value may have changed since it
// was installed, and a rule that is already gone is the normal case.
func TestRemoveStaleMarkPath(t *testing.T) {
	runner := &fakeRunner{}
	p := newNativePlugin(t, runner, func(context.Context, string) bool { return true })
	p.removeStaleMarkPath(context.Background(), 123, "1001")

	calls := strings.Join(runner.all(), "\n")
	if !strings.Contains(calls, "ip rule del fwmark 123 lookup 1001") {
		t.Fatalf("policy rule was not removed:\n%s", calls)
	}
	if !strings.Contains(calls, "ip route del default table 1001") {
		t.Fatalf("default route was not removed:\n%s", calls)
	}
	if strings.Contains(calls, "prio") {
		t.Fatalf("the delete still pins a priority:\n%s", calls)
	}
}

// TestRemoveStaleMarkPathRefusesUnsafeTargets makes sure the helper is not the
// place where a bad record turns into a deleted system object.
func TestRemoveStaleMarkPathRefusesUnsafeTargets(t *testing.T) {
	runner := &fakeRunner{}
	p := newNativePlugin(t, runner, func(context.Context, string) bool { return true })
	p.removeStaleMarkPath(context.Background(), 0, "1001")
	p.removeStaleMarkPath(context.Background(), 123, "main")
	p.removeStaleMarkPath(context.Background(), 123, "")
	if got := len(runner.all()); got != 0 {
		t.Fatalf("unsafe targets produced %d commands:\n%s", got, strings.Join(runner.all(), "\n"))
	}
}

// TestProxyStartRemovesTunSNAT covers the mode switch that used to leak a
// postrouting table: the outlet was direct once, so the table exists, and a
// proxied start never reaches the install branch that would own it.
func TestProxyStartRemovesTunSNAT(t *testing.T) {
	runner := &fakeRunner{}
	p := newNativePlugin(t, runner, func(context.Context, string) bool { return true })
	p.proxyActive = true
	p.setupTunEgress()

	if _, ok := runner.find("nft delete table ip " + p.tunSNATTableName()); !ok {
		t.Fatalf("proxied start left the snat table alone:\n%s", strings.Join(runner.all(), "\n"))
	}
}

// TestSweepLegacyMarkPath covers the migration case: a build that had no state
// table still leaves the mark inside its nft table, and that is enough to find
// and remove the policy rule it installed - without touching the marks VyOS
// keeps for itself.
func TestSweepLegacyMarkPath(t *testing.T) {
	runner := &fakeRunner{
		tableExists: true,
		tableDump: `table ip fakeip_test {
		chain mark_prerouting {
				ip daddr @real_ipv4 ip saddr != 198.18.0.0/16 meta mark set 0x0000007b
			}
		}`,
		ruleShow: "0:\tfrom all lookup local\n" +
			"10:\tfrom all fwmark 0xa lookup Oversea_Traffic_Table\n" +
			"1000:\tfrom all fwmark 0x7b lookup 123\n" +
			"32766:\tfrom all lookup main\n",
	}
	p := newNativePlugin(t, runner, func(context.Context, string) bool { return true })
	p.sweepLegacyMarkPath(context.Background())

	calls := strings.Join(runner.all(), "\n")
	if !strings.Contains(calls, "ip rule del fwmark 123 lookup 123") {
		t.Fatalf("the legacy policy rule was not removed:\n%s", calls)
	}
	if !strings.Contains(calls, "ip route del default table 123") {
		t.Fatalf("the legacy default route was not removed:\n%s", calls)
	}
	if strings.Contains(calls, "fwmark 10 lookup Oversea_Traffic_Table") {
		t.Fatalf("the sweep touched a foreign rule:\n%s", calls)
	}
}

// TestSweepLegacyMarkPathRespectsState keeps the sweep from running once the
// state table knows what this plugin installed.
func TestSweepLegacyMarkPathRespectsState(t *testing.T) {
	runner := &fakeRunner{
		tableExists: true,
		tableDump:   `chain mark_prerouting { meta mark set 0x0000007b }`,
		ruleShow:    "1000:\tfrom all fwmark 0x7b lookup 123\n",
	}
	p := newNativePlugin(t, runner, func(context.Context, string) bool { return true })
	p.saveMarkState(context.Background(), 123, "123")
	p.sweepLegacyMarkPath(context.Background())

	if got := len(runner.all()); got != 0 {
		t.Fatalf("sweep ran with a recorded state:\n%s", strings.Join(runner.all(), "\n"))
	}
}

// TestSweepLegacyMarkPathSkipsTheConfiguredMark: the normal path owns that rule
// and reinstalls it, so the sweep must not race it.
func TestSweepLegacyMarkPathSkipsTheConfiguredMark(t *testing.T) {
	runner := &fakeRunner{
		tableExists: true,
		tableDump:   `chain mark_prerouting { meta mark set 0x0000007b }`,
		ruleShow:    "1000:\tfrom all fwmark 0x7b lookup 123\n",
	}
	p := newNativePlugin(t, runner, func(context.Context, string) bool { return true })
	p.routeMark = 123
	p.routeTable = "123"
	p.sweepLegacyMarkPath(context.Background())

	if calls := strings.Join(runner.all(), "\n"); strings.Contains(calls, "rule del") {
		t.Fatalf("sweep touched the configured mark:\n%s", calls)
	}
}

// TestNonTunStartCleansTunOutlet covers the other direction of a mode switch:
// the run that used the device is gone, so its SNAT table and the policy rule
// pinning the range to the outlet table must not outlive it. The default route
// inside that table is left alone on purpose.
func TestNonTunStartCleansTunOutlet(t *testing.T) {
	runner := &fakeRunner{}
	p := newNativePlugin(t, runner, func(context.Context, string) bool { return true })
	p.cidr = "198.18.0.0/16"
	p.tunRouteTable = "101"
	p.cleanupStaleTunEgress(context.Background())

	calls := strings.Join(runner.all(), "\n")
	if !strings.Contains(calls, "nft delete table ip "+p.tunSNATTableName()) {
		t.Fatalf("snat table was left behind:\n%s", calls)
	}
	if !strings.Contains(calls, "ip rule del from 198.18.0.0/16 to ! 198.18.0.0/16 lookup 101") {
		t.Fatalf("outlet rule was left behind:\n%s", calls)
	}
	if strings.Contains(calls, "route del") {
		t.Fatalf("the sweep deleted a route it cannot own:\n%s", calls)
	}
}

// TestStaleNFTCleanupSkipsAbsentTable keeps the startup clean quiet: an object
// that is already gone must not produce a delete, which would otherwise look
// like a failure in the journal.
func TestStaleNFTCleanupSkipsAbsentTable(t *testing.T) {
	runner := &fakeRunner{}
	p := newNativePlugin(t, runner, func(context.Context, string) bool { return true })
	p.cleanupStaleNFTTable(context.Background())
	if calls := strings.Join(runner.all(), "\n"); strings.Contains(calls, "nft delete") {
		t.Fatalf("an absent table still produced a delete:\n%s", calls)
	}
}

// TestStaleSNATCleanupSkipsAbsentTable is the same for the proxied outlet.
func TestStaleSNATCleanupSkipsAbsentTable(t *testing.T) {
	runner := &fakeRunner{failContains: "nft list table ip " + "test_tun_snat"}
	p := newNativePlugin(t, runner, func(context.Context, string) bool { return true })
	p.removeStaleTunSNAT(context.Background())
	if calls := strings.Join(runner.all(), "\n"); strings.Contains(calls, "nft delete") {
		t.Fatalf("an absent table still produced a delete:\n%s", calls)
	}
}

// TestCommandMissingTellsThemApart pins the difference the cleanup log depends
// on: a missing binary is not the same as a missing table.
func TestCommandMissingTellsThemApart(t *testing.T) {
	_, err := exec.Command("definitely-not-a-real-binary-9f31", "--version").Output()
	if err == nil {
		t.Fatal("the probe binary unexpectedly exists")
	}
	if !commandMissing(err) {
		t.Fatalf("a missing binary was not recognised: %v", err)
	}
	if commandMissing(fmt.Errorf("exit status 1")) {
		t.Fatal("an ordinary command failure was treated as a missing binary")
	}
}
