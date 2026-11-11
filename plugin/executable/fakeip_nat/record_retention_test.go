package fakeipnat

import (
	"context"
	"testing"
	"time"
)

func TestParseRecordTTL(t *testing.T) {
	cases := []struct {
		in      string
		want    time.Duration
		wantErr bool
	}{
		{"", defaultRecordTTL, false},
		{"168h", 168 * time.Hour, false},
		{"24h", 24 * time.Hour, false},
		{"30m", 30 * time.Minute, false},
		{"0", 0, false},
		{"-1h", 0, true},
		{"7d", 0, true},
		{"abc", 0, true},
	}
	for _, c := range cases {
		got, err := parseRecordTTL(c.in)
		if c.wantErr {
			if err == nil {
				t.Fatalf("parseRecordTTL(%q) should fail", c.in)
			}
			continue
		}
		if err != nil {
			t.Fatalf("parseRecordTTL(%q): %v", c.in, err)
		}
		if got != c.want {
			t.Fatalf("parseRecordTTL(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func insertRetentionMapping(t *testing.T, p *FakeIPNatPlugin, domain, fakeIP string, created, seen int64) {
	t.Helper()
	if _, err := p.db.Exec(
		"INSERT INTO test_mapping (domain, fake_ip, created_at, last_seen) VALUES (?, ?, ?, ?)",
		domain, fakeIP, created, seen); err != nil {
		t.Fatalf("insert %s: %v", domain, err)
	}
}

func mappingCount(t *testing.T, p *FakeIPNatPlugin) int {
	t.Helper()
	var n int
	if err := p.db.QueryRow("SELECT COUNT(*) FROM test_mapping").Scan(&n); err != nil {
		t.Fatalf("count mappings: %v", err)
	}
	return n
}

func TestSweepDropsExpiredMappings(t *testing.T) {
	p := newTestPlugin(t, "198.18.0.0/24")
	p.recordTTL = 7 * 24 * time.Hour
	now := time.Now().Unix()
	tenDaysAgo := now - 10*24*3600

	insertRetentionMapping(t, p, "old.example", "198.18.0.2", tenDaysAgo, 0)
	insertRetentionMapping(t, p, "fresh.example", "198.18.0.3", now, now)
	p.runtime.put("old.example", "198.18.0.2")
	p.runtime.put("fresh.example", "198.18.0.3")

	p.sweepRecords(context.Background())

	if n := mappingCount(t, p); n != 1 {
		t.Fatalf("mapping rows after sweep = %d, want 1", n)
	}
	if p.runtime.taken("198.18.0.2") {
		t.Fatal("expired fake ip is still booked in the runtime table")
	}
	if !p.runtime.taken("198.18.0.3") {
		t.Fatal("fresh fake ip was released")
	}
}

func TestSweepKeepsTouchedDomainAndFlushesIt(t *testing.T) {
	p := newTestPlugin(t, "198.18.0.0/24")
	p.recordTTL = 7 * 24 * time.Hour
	now := time.Now().Unix()
	tenDaysAgo := now - 10*24*3600

	// The row looks old in SQLite, but the in-memory touch says it was queried
	// a second ago: it must survive and be written back.
	insertRetentionMapping(t, p, "touched.example", "198.18.0.2", tenDaysAgo, 0)
	p.runtime.put("touched.example", "198.18.0.2")
	p.runtime.touch("touched.example", now)

	p.sweepRecords(context.Background())

	if n := mappingCount(t, p); n != 1 {
		t.Fatalf("mapping rows after sweep = %d, want 1", n)
	}
	var seen int64
	if err := p.db.QueryRow("SELECT last_seen FROM test_mapping WHERE domain = ?", "touched.example").Scan(&seen); err != nil {
		t.Fatalf("read last_seen: %v", err)
	}
	if seen != now {
		t.Fatalf("last_seen = %d, want %d", seen, now)
	}
}

func TestSweepDropsStaleRealIPs(t *testing.T) {
	p := newTestPlugin(t, "198.18.0.0/24")
	p.recordTTL = 7 * 24 * time.Hour
	now := time.Now().Unix()
	tenDaysAgo := now - 10*24*3600

	if _, err := p.db.Exec(
		"INSERT INTO test_real_ips (domain, real_ip, last_seen) VALUES (?, ?, ?), (?, ?, ?)",
		"old.example", "1.1.1.1", tenDaysAgo, "fresh.example", "2.2.2.2", now); err != nil {
		t.Fatalf("insert real ips: %v", err)
	}
	p.sweepRecords(context.Background())

	var n int
	if err := p.db.QueryRow("SELECT COUNT(*) FROM test_real_ips").Scan(&n); err != nil {
		t.Fatalf("count real ips: %v", err)
	}
	if n != 1 {
		t.Fatalf("real ip rows after sweep = %d, want 1", n)
	}
}

func TestSweptOffsetIsReused(t *testing.T) {
	p := newTestPlugin(t, "198.18.0.0/28")
	ctx := context.Background()

	a, err := p.recordAndAllocate(ctx, "a.example", []string{"1.1.1.1"})
	if err != nil {
		t.Fatalf("allocate a: %v", err)
	}
	b, err := p.recordAndAllocate(ctx, "b.example", []string{"2.2.2.2"})
	if err != nil {
		t.Fatalf("allocate b: %v", err)
	}
	if a == b {
		t.Fatalf("two domains share the same fake ip %s", a)
	}

	// Simulate the retention sweep releasing a's address.
	if _, err := p.db.Exec("DELETE FROM test_mapping WHERE domain = ?", "a.example"); err != nil {
		t.Fatalf("drop a: %v", err)
	}
	p.runtime.remove("a.example")

	c, err := p.recordAndAllocate(ctx, "c.example", []string{"3.3.3.3"})
	if err != nil {
		t.Fatalf("allocate c: %v", err)
	}
	if c != a {
		t.Fatalf("new domain got %s, want the freed address %s", c, a)
	}
}
