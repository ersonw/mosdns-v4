package fakeipnat

// These tests pin the rule that an address inside the plugin's own range is
// never used as a destination. It can reach the code from an upstream answer,
// a stale row written before the guard existed, or a resolver that is the
// plugin itself; every such path must drop it instead of dialing it.

import (
	"context"
	"testing"
	"time"
)

func TestIsFakeAddrGuardsTheOwnRange(t *testing.T) {
	p := newRealIPPlugin(t, false) // IPv4Range 198.18.0.0/16

	if !p.isFakeAddrString("198.18.0.7") {
		t.Fatal("an address of the configured range must count as fake")
	}
	if p.isFakeAddrString("198.19.0.7") {
		t.Fatal("an address outside the configured range must not count as fake")
	}
	if p.isFakeAddrString("www.google.com") {
		t.Fatal("a name must never count as a fake address")
	}
	if p.isFakeAddrString("") {
		t.Fatal("an empty value must not count as a fake address")
	}
}

// The write side: an upstream that answers with one of our own fake addresses
// must not have it stored as a real ip.
func TestUpsertRealIPsDropsFakeValues(t *testing.T) {
	p := newRealIPPlugin(t, false)
	ctx := context.Background()
	now := time.Now().Unix()

	if err := p.upsertRealIPs(ctx, "example.com", []string{"198.18.0.7", "93.184.216.34"}, now); err != nil {
		t.Fatalf("upsertRealIPs failed: %v", err)
	}

	var fakeCount int
	if err := p.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM "+p.ipTable+" WHERE domain = ? AND real_ip LIKE '198.18.%'",
		"example.com").Scan(&fakeCount); err != nil {
		t.Fatalf("count fake rows failed: %v", err)
	}
	if fakeCount != 0 {
		t.Fatalf("stored %d fake address(es) as real ips", fakeCount)
	}

	var realCount int
	if err := p.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM "+p.ipTable+" WHERE domain = ? AND real_ip = ?",
		"example.com", "93.184.216.34").Scan(&realCount); err != nil {
		t.Fatalf("count real rows failed: %v", err)
	}
	if realCount != 1 {
		t.Fatalf("real address row count = %d, want 1", realCount)
	}
}

// The read side: a row written by an older build must not become the
// destination while the newest row is still a fake address.
func TestPrimaryRealIPSkipsFakeRows(t *testing.T) {
	p := newRealIPPlugin(t, false)
	ctx := context.Background()
	now := time.Now().Unix()

	if _, err := p.db.ExecContext(ctx,
		"INSERT INTO "+p.ipTable+" (domain, real_ip, last_seen) VALUES (?,?,?)",
		"example.com", "93.184.216.34", now-100); err != nil {
		t.Fatalf("insert old real row failed: %v", err)
	}
	if _, err := p.db.ExecContext(ctx,
		"INSERT INTO "+p.ipTable+" (domain, real_ip, last_seen) VALUES (?,?,?)",
		"example.com", "198.18.0.7", now); err != nil {
		t.Fatalf("insert fake row failed: %v", err)
	}

	addr, err := p.primaryRealIP(ctx, "example.com")
	if err != nil {
		t.Fatalf("primaryRealIP failed: %v", err)
	}
	if addr.String() != "93.184.216.34" {
		t.Fatalf("primaryRealIP = %s, want the real address behind the fake row", addr)
	}
}

// When every row is a fake address the lookup reports "no real ip" instead of
// handing one back.
func TestPrimaryRealIPRefusesAllFakeRows(t *testing.T) {
	p := newRealIPPlugin(t, false)
	ctx := context.Background()
	now := time.Now().Unix()

	if _, err := p.db.ExecContext(ctx,
		"INSERT INTO "+p.ipTable+" (domain, real_ip, last_seen) VALUES (?,?,?)",
		"example.com", "198.18.0.7", now); err != nil {
		t.Fatalf("insert fake row failed: %v", err)
	}

	if _, err := p.primaryRealIP(ctx, "example.com"); err == nil {
		t.Fatal("a domain with only fake addresses must not resolve to a target")
	}
}

// The reverse lookup: a mapping row whose "domain" is itself an address of the
// range can only produce a fake target, so it is rejected with a reason.
func TestDomainForFakeIPRejectsFakeDomain(t *testing.T) {
	p := newRealIPPlugin(t, false)
	ctx := context.Background()
	now := time.Now().Unix()

	if _, err := p.db.ExecContext(ctx,
		"INSERT INTO "+p.mapTable+" (domain, fake_ip, created_at, last_seen) VALUES (?,?,?,?)",
		"198.18.0.5", "198.18.0.9", now, now); err != nil {
		t.Fatalf("insert poisoned mapping failed: %v", err)
	}

	if _, err := p.domainForFakeIP(ctx, "198.18.0.9"); err == nil {
		t.Fatal("a mapping naming a fake ip as its domain must be refused")
	}
}

// Candidate selection must keep only addresses that can actually be reached.
func TestRealCandidatesSplitFakeAddresses(t *testing.T) {
	p := newRealIPPlugin(t, false)

	kept, fake := p.realCandidates([]string{"93.184.216.34", "198.18.0.7", "142.250.0.1"})
	if len(kept) != 2 {
		t.Fatalf("kept = %v, want two real addresses", kept)
	}
	if len(fake) != 1 || fake[0] != "198.18.0.7" {
		t.Fatalf("fake = %v, want the fake address only", fake)
	}
	for _, ip := range kept {
		if ip == "198.18.0.7" {
			t.Fatal("a fake address survived candidate filtering")
		}
	}
}
