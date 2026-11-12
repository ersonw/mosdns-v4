package fakeipnat

import (
	"context"
	"database/sql"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/ersonw/mosdns-v4/coremain"
	"github.com/ersonw/mosdns-v4/pkg/query_context"
	"github.com/miekg/dns"
	"go.uber.org/zap"
)

func TestParseAccessTTL(t *testing.T) {
	tests := []struct {
		raw     string
		want    time.Duration
		wantErr bool
	}{
		{"", defaultAccessTTL, false},
		{"0", 0, false},
		{"168h", 168 * time.Hour, false},
		{" 30m ", 30 * time.Minute, false},
		{"-1h", 0, true},
		{"nonsense", 0, true},
	}
	for _, tt := range tests {
		got, err := parseAccessTTL(tt.raw)
		if tt.wantErr {
			if err == nil {
				t.Errorf("parseAccessTTL(%q) = nil error, want failure", tt.raw)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseAccessTTL(%q) unexpected error: %v", tt.raw, err)
			continue
		}
		if got != tt.want {
			t.Errorf("parseAccessTTL(%q) = %v, want %v", tt.raw, got, tt.want)
		}
	}
}

// newAccessTestPlugin builds just enough of the plugin to exercise the access
// table: the database and the two table names are all its methods touch.
func newAccessTestPlugin(t *testing.T) *FakeIPNatPlugin {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fakeip.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	if _, err := db.Exec(`CREATE TABLE default_real (
		domain TEXT NOT NULL, real_ip TEXT NOT NULL, last_seen INTEGER DEFAULT 0,
		PRIMARY KEY (domain, real_ip))`); err != nil {
		t.Fatalf("create real table: %v", err)
	}
	if err := ensureAccessTable(db, "default_access"); err != nil {
		t.Fatalf("create access table: %v", err)
	}

	p := &FakeIPNatPlugin{
		BP: coremain.NewBP("test_fakeip", PluginType, zap.NewNop(), nil),
		db: db, ipTable: "default_real", accessTable: "default_access", accessLog: true,
	}
	return p
}

func TestRecordAccessAggregatesPerClientDomain(t *testing.T) {
	p := newAccessTestPlugin(t)
	meta := &query_context.RequestMeta{ClientAddr: netip.MustParseAddr("::ffff:192.0.2.10")}
	// Unmap must turn the v4-mapped address into the plain v4 form, otherwise
	// the same client would appear twice in the export.
	for i := 0; i < 2; i++ {
		q := new(dns.Msg)
		q.SetQuestion("example.com.", dns.TypeA)
		p.recordAccess(query_context.NewContext(q, meta), "example.com", "198.18.0.5")
	}

	records, err := p.AdminAccessRecords(context.Background(), []string{"192.0.2.10"}, 0, 100)
	if err != nil {
		t.Fatalf("AdminAccessRecords: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("got %d rows, want 1 (one per client+domain)", len(records))
	}
	if records[0].Hits != 2 {
		t.Errorf("hits = %d, want 2", records[0].Hits)
	}
	if records[0].FakeIP != "198.18.0.5" {
		t.Errorf("fake ip = %q", records[0].FakeIP)
	}
	if records[0].FirstSeen == 0 || records[0].LastSeen == 0 {
		t.Errorf("timestamps not set: %+v", records[0])
	}
}

func TestRecordAccessIgnoresMissingClient(t *testing.T) {
	p := newAccessTestPlugin(t)
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	p.recordAccess(query_context.NewContext(q, nil), "example.com", "198.18.0.5")

	records, err := p.AdminAccessRecords(context.Background(), []string{"192.0.2.10"}, 0, 100)
	if err != nil {
		t.Fatalf("AdminAccessRecords: %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("got %d rows for an unattributable query", len(records))
	}
}

func TestAdminAccessRecordsJoinsRealIPAndFilters(t *testing.T) {
	p := newAccessTestPlugin(t)
	now := time.Now().Unix()
	rows := []struct {
		client, domain, fake string
		last                 int64
	}{
		{"192.0.2.10", "old.example.com", "198.18.0.2", now - 3600},
		{"192.0.2.10", "new.example.com", "198.18.0.3", now},
		{"192.0.2.11", "other.example.com", "198.18.0.4", now},
	}
	for _, r := range rows {
		if _, err := p.db.Exec(`INSERT INTO default_access (client_ip, domain, fake_ip, first_seen, last_seen, hits)
			VALUES (?, ?, ?, ?, ?, 1)`, r.client, r.domain, r.fake, r.last, r.last); err != nil {
			t.Fatalf("insert access row: %v", err)
		}
	}
	// The real ip is learned for one domain only; the join must leave the
	// others empty instead of dropping them.
	if _, err := p.db.Exec(`INSERT INTO default_real (domain, real_ip, last_seen)
		VALUES ('new.example.com', '203.0.113.7', ?)`, now); err != nil {
		t.Fatalf("insert real ip: %v", err)
	}

	records, err := p.AdminAccessRecords(context.Background(), []string{"192.0.2.10"}, 0, 100)
	if err != nil {
		t.Fatalf("AdminAccessRecords: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("got %d rows, want 2", len(records))
	}
	// Newest first.
	if records[0].Domain != "new.example.com" {
		t.Errorf("first row = %q, want newest domain", records[0].Domain)
	}
	if records[0].RealIP != "203.0.113.7" {
		t.Errorf("real ip = %q, want joined value", records[0].RealIP)
	}
	if records[1].RealIP != "" {
		t.Errorf("real ip = %q, want empty for an unknown domain", records[1].RealIP)
	}

	// since filters out the older row.
	records, err = p.AdminAccessRecords(context.Background(), []string{"192.0.2.10"}, now-60, 100)
	if err != nil {
		t.Fatalf("AdminAccessRecords with since: %v", err)
	}
	if len(records) != 1 || records[0].Domain != "new.example.com" {
		t.Errorf("since filter returned %+v", records)
	}

	// limit is honoured.
	records, err = p.AdminAccessRecords(context.Background(), []string{"192.0.2.10"}, 0, 1)
	if err != nil {
		t.Fatalf("AdminAccessRecords with limit: %v", err)
	}
	if len(records) != 1 {
		t.Errorf("limit returned %d rows, want 1", len(records))
	}
}

func TestSweepAccessDropsOnlyExpired(t *testing.T) {
	p := newAccessTestPlugin(t)
	p.accessTTL = time.Hour
	now := time.Now().Unix()
	if _, err := p.db.Exec(`INSERT INTO default_access (client_ip, domain, fake_ip, first_seen, last_seen, hits)
		VALUES ('192.0.2.10', 'fresh.example.com', '198.18.0.2', ?, ?, 1)`, now-60, now-60); err != nil {
		t.Fatalf("insert fresh: %v", err)
	}
	if _, err := p.db.Exec(`INSERT INTO default_access (client_ip, domain, fake_ip, first_seen, last_seen, hits)
		VALUES ('192.0.2.10', 'stale.example.com', '198.18.0.3', ?, ?, 1)`, now-7200, now-7200); err != nil {
		t.Fatalf("insert stale: %v", err)
	}

	p.sweepAccess(context.Background())

	var count int
	if err := p.db.QueryRow(`SELECT COUNT(*) FROM default_access`).Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 1 {
		t.Errorf("rows after sweep = %d, want 1", count)
	}
	var domain string
	if err := p.db.QueryRow(`SELECT domain FROM default_access`).Scan(&domain); err != nil {
		t.Fatalf("select survivor: %v", err)
	}
	if domain != "fresh.example.com" {
		t.Errorf("survivor = %q, want the fresh row", domain)
	}
}
