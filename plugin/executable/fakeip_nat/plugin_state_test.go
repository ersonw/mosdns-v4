package fakeipnat

import (
	"context"
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
