package fakeipnat

import (
	"context"
	"net/netip"
	"path/filepath"
	"sync"
	"testing"

	"github.com/ersonw/mosdns-v4/coremain"
	"go.uber.org/zap"
)

func newTestPlugin(t *testing.T, ipv4Range string) *FakeIPNatPlugin {
	t.Helper()
	bp := coremain.NewBP("test_fakeip", PluginType, zap.NewNop(), nil)
	dbPath := filepath.Join(t.TempDir(), "fakeip.db")
	// RecordTTL "0" keeps the background sweep off in unit tests; a test that
	// needs it sets p.recordTTL itself and calls sweepRecords directly.
	p, err := Init(bp, &Args{
		DBPath:      dbPath,
		TablePrefix: "test",
		IPv4Range:   ipv4Range,
		RecordTTL:   "0",
	})
	if err != nil {
		t.Fatalf("Init(%s) failed: %v", ipv4Range, err)
	}
	fp := p.(*FakeIPNatPlugin)
	t.Cleanup(func() { _ = fp.Close() })
	return fp
}

func TestRejectIPv6Range(t *testing.T) {
	bp := coremain.NewBP("test_fakeip", PluginType, zap.NewNop(), nil)
	_, err := Init(bp, &Args{
		DBPath:      filepath.Join(t.TempDir(), "fakeip.db"),
		TablePrefix: "test",
		IPv4Range:   "2001:db8::/32",
	})
	if err == nil {
		t.Fatal("expected an error for an IPv6 prefix, got nil")
	}
}

func TestRejectTooSmallRange(t *testing.T) {
	bp := coremain.NewBP("test_fakeip", PluginType, zap.NewNop(), nil)
	_, err := Init(bp, &Args{
		DBPath:      filepath.Join(t.TempDir(), "fakeip.db"),
		TablePrefix: "test",
		IPv4Range:   "198.18.0.0/31",
	})
	if err == nil {
		t.Fatal("expected an error for a prefix without usable hosts, got nil")
	}
}

func TestAllocateInsidePrefix(t *testing.T) {
	p := newTestPlugin(t, "198.18.0.0/16")
	if p.maxHosts != 65534 {
		t.Fatalf("maxHosts = %d, want 65534", p.maxHosts)
	}
	for _, id := range []uint64{1, 2, 1000, 65533, 65534, 65535, 1 << 40} {
		got, err := p.allocateFakeIP(id)
		if err != nil {
			t.Fatalf("allocateFakeIP(%d) failed: %v", id, err)
		}
		addr, err := netip.ParseAddr(got)
		if err != nil {
			t.Fatalf("allocateFakeIP(%d) returned invalid ip %q: %v", id, got, err)
		}
		if !addr.Is4() || !p.prefix.Contains(addr) {
			t.Fatalf("allocateFakeIP(%d) = %s, not inside %s", id, got, p.prefix)
		}
		if addr == p.prefix.Addr() {
			t.Fatalf("allocateFakeIP(%d) returned the network address %s", id, got)
		}
	}
}

func TestRecordAndAllocateStable(t *testing.T) {
	p := newTestPlugin(t, "198.18.0.0/16")
	ctx := context.Background()

	first, err := p.recordAndAllocate(ctx, "example.com", []string{"1.2.3.4", "5.6.7.8"})
	if err != nil {
		t.Fatalf("first allocation failed: %v", err)
	}
	second, err := p.recordAndAllocate(ctx, "example.com", []string{"9.9.9.9"})
	if err != nil {
		t.Fatalf("second allocation failed: %v", err)
	}
	if first != second {
		t.Fatalf("fake ip changed between queries: %s -> %s", first, second)
	}
	if first == pendingFakeIP {
		t.Fatal("allocated fake ip is still pending")
	}

	var count int
	if err := p.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM test_mapping").Scan(&count); err != nil {
		t.Fatalf("count mapping failed: %v", err)
	}
	if count != 1 {
		t.Fatalf("mapping rows = %d, want 1", count)
	}
	if err := p.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM test_real_ips").Scan(&count); err != nil {
		t.Fatalf("count real ips failed: %v", err)
	}
	if count != 3 {
		t.Fatalf("real ip rows = %d, want 3", count)
	}
}

func TestPendingRowIsRecovered(t *testing.T) {
	p := newTestPlugin(t, "198.18.0.0/16")
	ctx := context.Background()

	// Simulate a crash between INSERT and UPDATE.
	if _, err := p.db.ExecContext(ctx,
		"INSERT INTO test_mapping (domain, fake_ip, created_at) VALUES (?, ?, ?)",
		"crash.example", pendingFakeIP, 0); err != nil {
		t.Fatalf("seed pending row failed: %v", err)
	}

	got, err := p.recordAndAllocate(ctx, "crash.example", []string{"1.1.1.1"})
	if err != nil {
		t.Fatalf("recover pending row failed: %v", err)
	}
	addr, err := netip.ParseAddr(got)
	if err != nil || !p.prefix.Contains(addr) {
		t.Fatalf("recovered ip %q is not usable: %v", got, err)
	}
}

func TestConcurrentAllocationIsIdempotent(t *testing.T) {
	p := newTestPlugin(t, "198.18.0.0/16")
	ctx := context.Background()

	const workers = 32
	results := make(chan string, workers)
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ip, err := p.recordAndAllocate(ctx, "same.example", []string{"2.2.2.2"})
			if err != nil {
				errs <- err
				return
			}
			results <- ip
		}()
	}
	wg.Wait()
	close(results)
	close(errs)

	for err := range errs {
		t.Fatalf("concurrent allocation error: %v", err)
	}
	var first string
	for ip := range results {
		if first == "" {
			first = ip
			continue
		}
		if ip != first {
			t.Fatalf("same domain got different fake ips: %s and %s", first, ip)
		}
	}
	if first == "" {
		t.Fatal("no result returned")
	}

	// Distinct domains must not collide.
	seen := map[string]string{}
	for _, d := range []string{"a.example", "b.example", "c.example", "d.example"} {
		ip, err := p.recordAndAllocate(ctx, d, []string{"3.3.3.3"})
		if err != nil {
			t.Fatalf("allocate %s failed: %v", d, err)
		}
		if other, ok := seen[ip]; ok {
			t.Fatalf("%s and %s share fake ip %s", d, other, ip)
		}
		seen[ip] = d
	}
}
