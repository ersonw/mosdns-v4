package fakeipnat

// Tests for the managed route ledger: every installed prefix is recorded, and a
// stop or a restart removes exactly those prefixes again.

import (
	"context"
	"strings"
	"testing"
)

func ledgerRowCount(t *testing.T, p *FakeIPNatPlugin) int {
	t.Helper()
	var n int
	if err := p.db.QueryRow("SELECT COUNT(*) FROM " + p.routesTable).Scan(&n); err != nil {
		t.Fatalf("count ledger rows failed: %v", err)
	}
	return n
}

func TestLedgerRecordsInstalledRoutes(t *testing.T) {
	p := newRealIPPlugin(t, true)
	ctx := context.Background()

	p.applyHostRoute(ctx, "1.2.3.4", "11.10.12.1", "wg0")
	p.applyHostRoute(ctx, "5.6.7.8", "11.10.12.1", "wg0")

	// The answer path must not wait on SQLite: both rows are in memory, and the
	// database still has none.
	if got := p.ledgerSize(); got != 2 {
		t.Fatalf("memory rows = %d, want 2", got)
	}
	if got := ledgerRowCount(t, p); got != 0 {
		t.Fatalf("database rows = %d before the flush, want 0", got)
	}

	p.flushLedger(ctx)
	if got := ledgerRowCount(t, p); got != 2 {
		t.Fatalf("ledger rows = %d after the flush, want 2", got)
	}

	routes, err := p.ledgerRoutes(ctx)
	if err != nil {
		t.Fatalf("read ledger failed: %v", err)
	}
	found := false
	for _, r := range routes {
		if r.prefix == "1.2.3.4/32" && r.nextHop == "11.10.12.1" && r.dev == "wg0" {
			found = true
		}
	}
	if !found {
		t.Fatalf("1.2.3.4/32 not recorded with the values it was written with: %+v", routes)
	}
}

func TestSweepLedgerRemovesRecordedPrefixes(t *testing.T) {
	p := newRealIPPlugin(t, false)
	ctx := context.Background()

	// Rows a previous process would have left behind, including an aggregated
	// block that no longer matches any single /32.
	p.rememberManagedRoute(ctx, "1.2.3.4/32", "11.10.12.1", "wg0")
	p.rememberManagedRoute(ctx, "1.2.3.0/24", "", "wg0")

	runner := p.runner.(*fakeRunner)
	deleted := p.sweepLedgerRoutes(ctx)
	if deleted == 0 {
		t.Fatal("sweep reported no deleted route")
	}
	// The delete command differs per platform (linux names the CIDR, the bsd
	// family uses -host / -net + -netmask), so the address is what the test
	// looks for.
	for _, addr := range []string{"1.2.3.4", "1.2.3.0"} {
		if _, ok := runner.find(addr); !ok {
			t.Fatalf("no delete command mentioned %s: %v", addr, runner.all())
		}
	}
	if got := ledgerRowCount(t, p); got != 0 {
		t.Fatalf("ledger still holds %d rows after the sweep", got)
	}
}

func TestKnownRealIPsIncludesDatabaseRows(t *testing.T) {
	// In realip mode the memory set starts empty on every restart, so the
	// database is the only thing that can tell a startup sweep which routes are
	// this plugin's.
	p := newRealIPPlugin(t, true)
	ctx := context.Background()
	if _, err := p.db.ExecContext(ctx,
		"INSERT INTO "+p.ipTable+" (domain, real_ip, last_seen) VALUES (?,?,?)",
		"example.com", "93.184.216.34", 1); err != nil {
		t.Fatalf("seed real ip failed: %v", err)
	}

	known := p.knownRealIPs(ctx)
	found := false
	for _, addr := range known {
		if addr.String() == "93.184.216.34" {
			found = true
		}
	}
	if !found {
		t.Fatalf("database address missing from known real ips: %v", known)
	}
}

func TestCleanupEmptiesTheLedger(t *testing.T) {
	p := newRealIPPlugin(t, true)
	ctx := context.Background()
	p.rememberManagedRoute(ctx, "1.2.3.4/32", "11.10.12.1", "wg0")

	p.cleanupDataPath()

	if got := ledgerRowCount(t, p); got != 0 {
		t.Fatalf("ledger still holds %d rows after cleanup", got)
	}
	runner := p.runner.(*fakeRunner)
	if !strings.Contains(strings.Join(runner.all(), "\n"), "1.2.3.4") {
		t.Fatalf("cleanup issued no command for the recorded prefix: %v", runner.all())
	}
}

// TestLedgerForgetReachesTheDatabase pins the other direction: a prefix removed
// from memory is deleted from the record by the next flush, not immediately.
func TestLedgerForgetReachesTheDatabase(t *testing.T) {
	p := newRealIPPlugin(t, true)
	ctx := context.Background()

	p.rememberManagedRoute(ctx, "1.2.3.4/32", "11.10.12.1", "wg0")
	p.flushLedger(ctx)
	if got := ledgerRowCount(t, p); got != 1 {
		t.Fatalf("ledger rows = %d after the first flush, want 1", got)
	}

	p.forgetManagedRoute(ctx, "1.2.3.4/32")
	if got := ledgerRowCount(t, p); got != 1 {
		t.Fatalf("the forget should not hit the database, rows = %d", got)
	}
	p.flushLedger(ctx)
	if got := ledgerRowCount(t, p); got != 0 {
		t.Fatalf("ledger rows = %d after the forget was flushed, want 0", got)
	}
}

// TestLedgerOwnsOnlyItsRoutes pins the cleanup guard: a scanned prefix is only
// ours when the ledger recorded it verbatim or it is exactly the aggregate an
// earlier collapse pass installed. An operator route that merely looks similar
// stays untouched.
func TestLedgerOwnsOnlyItsRoutes(t *testing.T) {
	p := newRealIPPlugin(t, true)
	ctx := context.Background()

	p.rememberManagedRoute(ctx, "1.2.3.4/32", "11.10.12.1", "wg0")
	p.rememberManagedRoute(ctx, "1.2.3.5/32", "11.10.12.1", "wg0")

	if !p.ledgerOwnsPrefix("1.2.3.4/32") {
		t.Fatalf("a recorded prefix must count as ours")
	}
	if !p.ledgerOwnsPrefix("1.2.3.4/31") {
		t.Fatalf("the aggregate of two recorded siblings must count as ours")
	}
	for _, foreign := range []string{"1.2.3.0/24", "1.2.0.0/16", "9.9.9.9/32"} {
		if p.ledgerOwnsPrefix(foreign) {
			t.Fatalf("%s has no ledger record but was treated as ours", foreign)
		}
		if !p.foreignRoute(foreign) {
			t.Fatalf("%s must be reported as somebody else's route", foreign)
		}
	}
	if p.foreignRoute("1.2.3.4/32") {
		t.Fatalf("a recorded prefix was reported as foreign")
	}
}
