package fakeipnat

import (
	"context"
	"testing"
)

func insertMapping(t *testing.T, p *FakeIPNatPlugin, domain, fakeIP string, createdAt int64) {
	t.Helper()
	if _, err := p.db.ExecContext(context.Background(),
		"INSERT INTO "+p.mapTable+" (domain, fake_ip, created_at) VALUES (?, ?, ?)",
		domain, fakeIP, createdAt); err != nil {
		t.Fatalf("insert %s: %v", domain, err)
	}
	p.runtime.put(domain, fakeIP)
}

func TestAdminMappingOperations(t *testing.T) {
	p := newTestPlugin(t, "198.18.0.0/15")
	ctx := context.Background()

	insertMapping(t, p, "a.example.com", "198.18.0.2", 1700000000)
	insertMapping(t, p, "b.example.com", "198.18.0.3", 1700000001)
	insertMapping(t, p, "c.example.com", pendingFakeIP, 1700000002)

	list, err := p.AdminListMappings(ctx, 2)
	if err != nil {
		t.Fatalf("AdminListMappings: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("listed %d entries, want 2", len(list))
	}
	if list[0].Domain != "c.example.com" {
		t.Fatalf("entries are not newest first: %+v", list)
	}

	e, ok, err := p.AdminLookupDomain(ctx, "b.example.com")
	if err != nil || !ok {
		t.Fatalf("AdminLookupDomain: ok=%v err=%v", ok, err)
	}
	if e.FakeIP != "198.18.0.3" {
		t.Fatalf("lookup returned %+v", e)
	}

	rev, ok, err := p.AdminLookupFakeIP(ctx, "198.18.0.2")
	if err != nil || !ok || rev.Domain != "a.example.com" {
		t.Fatalf("AdminLookupFakeIP = %+v ok=%v err=%v", rev, ok, err)
	}

	stats, err := p.AdminStats(ctx)
	if err != nil {
		t.Fatalf("AdminStats: %v", err)
	}
	if stats.Mappings != 3 || stats.Pending != 1 || stats.Runtime != 3 {
		t.Fatalf("stats = %+v", stats)
	}

	deleted, err := p.AdminDeleteDomain(ctx, "a.example.com")
	if err != nil || !deleted {
		t.Fatalf("AdminDeleteDomain: deleted=%v err=%v", deleted, err)
	}
	if _, ok := p.runtime.fakeOf("a.example.com"); ok {
		t.Fatalf("runtime entry survived deletion")
	}
	if _, ok, _ := p.AdminLookupDomain(ctx, "a.example.com"); ok {
		t.Fatalf("database row survived deletion")
	}

	deleted, err = p.AdminDeleteDomain(ctx, "missing.example.com")
	if err != nil || deleted {
		t.Fatalf("deleting a missing domain: deleted=%v err=%v", deleted, err)
	}

	n, err := p.AdminClearMappings(ctx)
	if err != nil {
		t.Fatalf("AdminClearMappings: %v", err)
	}
	if n != 2 {
		t.Fatalf("cleared %d rows, want 2", n)
	}
	if p.runtime.size() != 0 {
		t.Fatalf("runtime still has %d entries", p.runtime.size())
	}
}
