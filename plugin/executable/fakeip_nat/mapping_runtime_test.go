package fakeipnat

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ersonw/mosdns-v4/coremain"
	"go.uber.org/zap"
)

// A restart must not forget what earlier runs already mapped: the runtime table
// is rebuilt from SQLite before the first query arrives.
func TestRuntimeMappingsRestoredFromSQLite(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "fakeip.db")
	args := &Args{DBPath: dbPath, TablePrefix: "test", IPv4Range: "198.18.0.0/16"}

	bp := coremain.NewBP("test_fakeip", PluginType, zap.NewNop(), nil)
	p1, err := Init(bp, args)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	fp1 := p1.(*FakeIPNatPlugin)
	ctx := context.Background()
	fakeExample, err := fp1.recordAndAllocate(ctx, "example.com", []string{"1.2.3.4"})
	if err != nil {
		t.Fatalf("recordAndAllocate(example.com): %v", err)
	}
	fakeBaidu, err := fp1.recordAndAllocate(ctx, "baidu.com", []string{"5.6.7.8"})
	if err != nil {
		t.Fatalf("recordAndAllocate(baidu.com): %v", err)
	}
	if fp1.runtime.size() != 2 {
		t.Fatalf("runtime size after allocation = %d, want 2", fp1.runtime.size())
	}
	_ = fp1.Close()

	bp2 := coremain.NewBP("test_fakeip", PluginType, zap.NewNop(), nil)
	p2, err := Init(bp2, &Args{DBPath: dbPath, TablePrefix: "test", IPv4Range: "198.18.0.0/16"})
	if err != nil {
		t.Fatalf("re-Init: %v", err)
	}
	fp2 := p2.(*FakeIPNatPlugin)
	defer fp2.Close()

	if fp2.runtime.size() != 2 {
		t.Fatalf("restored runtime size = %d, want 2", fp2.runtime.size())
	}
	if domain, ok := fp2.runtime.domainOf(fakeExample); !ok || domain != "example.com" {
		t.Fatalf("fake %s -> %q (ok=%v), want example.com", fakeExample, domain, ok)
	}
	if domain, ok := fp2.runtime.domainOf(fakeBaidu); !ok || domain != "baidu.com" {
		t.Fatalf("fake %s -> %q (ok=%v), want baidu.com", fakeBaidu, domain, ok)
	}
	if fake, ok := fp2.runtime.fakeOf("example.com"); !ok || fake != fakeExample {
		t.Fatalf("example.com -> %q (ok=%v), want %s", fake, ok, fakeExample)
	}
}

// On the NAT path the nft map can hold an entry whose row was lost, and the
// database can hold a row the map is missing. Startup has to swap the two.
func TestReconcileFirewallMappings(t *testing.T) {
	fp := newTestPlugin(t, "198.18.0.0/16")
	ctx := context.Background()
	fake, err := fp.recordAndAllocate(ctx, "example.com", []string{"1.2.3.4"})
	if err != nil {
		t.Fatalf("recordAndAllocate: %v", err)
	}

	// The firewall still knows an address that has no database row, and it is
	// missing the example.com entry that was just allocated.
	fr := &fakeRunner{
		tableExists: true,
		mappings:    "elements = { 198.18.0.9 : 9.9.9.9 }",
	}
	fp.runner = fr
	fp.reconcileFirewallMappings(ctx)

	if !fp.runtime.isReserved("198.18.0.9") {
		t.Fatal("firewall-only fake ip must be reserved")
	}
	if _, ok := fp.runtime.domainOf("198.18.0.9"); ok {
		t.Fatal("firewall-only fake ip must not resolve to a domain")
	}

	refill, ok := fr.find("add element ip fakeip_test dnat_map")
	if !ok {
		t.Fatalf("missing mapping was not refilled, calls: %v", fr.all())
	}
	if !strings.Contains(refill, fake+" : 1.2.3.4") {
		t.Fatalf("refill command = %q, want %s : 1.2.3.4", refill, fake)
	}
}
