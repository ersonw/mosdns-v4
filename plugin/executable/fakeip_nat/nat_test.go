package fakeipnat

import (
	"context"
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/ersonw/mosdns-v4/coremain"
	"github.com/ersonw/mosdns-v4/pkg/utils"
	"go.uber.org/zap"
)

// fakeRunner records every command and answers the few probes syncNAT makes.
type fakeRunner struct {
	mu           sync.Mutex
	calls        []string
	tableExists  bool
	mappings     string            // output of `nft list map`
	failContains string            // every command containing this string fails
	devExists    bool              // `ip link show dev X` succeeds for any name
	devs         map[string]bool   // per-name existence, takes precedence over devExists
	devAddrs     map[string]string // output of `ip addr show dev X`
	ifaces       map[string]bool   // `ifconfig X` answers; nil means every probe succeeds
	routes       string            // output of `ip -4 route show`
}

func (f *fakeRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	call := name + " " + strings.Join(args, " ")

	f.mu.Lock()
	f.calls = append(f.calls, call)
	f.mu.Unlock()

	if f.failContains != "" && strings.Contains(call, f.failContains) {
		return "", fmt.Errorf("fake failure: %s", call)
	}

	switch {
	case call == "nft list table ip fakeip_test":
		if f.tableExists {
			return "", nil
		}
		return "", fmt.Errorf("no such file or directory")
	case strings.HasPrefix(call, "nft list map"):
		if f.mappings == "" {
			return "", fmt.Errorf("no map")
		}
		return f.mappings, nil
	case call == "ip route show default":
		return "default via 10.0.0.1 dev eth0", nil
	case call == "ip -4 route show" || strings.HasPrefix(call, "ip -4 route show table "):
		return f.routes, nil
	case strings.HasPrefix(call, "ip link show dev "):
		name := strings.TrimPrefix(call, "ip link show dev ")
		if f.devs != nil {
			if f.devs[name] {
				return "", nil
			}
			return "", fmt.Errorf("device does not exist")
		}
		if f.devExists {
			return "", nil
		}
		return "", fmt.Errorf("device does not exist")
	case strings.HasPrefix(call, "ifconfig "):
		if f.ifaces == nil {
			return "", nil
		}
		iface := strings.TrimPrefix(call, "ifconfig ")
		if f.ifaces[iface] {
			return "flags=8051<UP,POINTOPOINT,RUNNING>", nil
		}
		return "", fmt.Errorf("ifconfig: interface %s does not exist", iface)
	case strings.HasPrefix(call, "ip addr show dev "):
		name := strings.TrimPrefix(call, "ip addr show dev ")
		if addr, ok := f.devAddrs[name]; ok {
			return "inet " + addr + "/32 scope global " + name, nil
		}
		return "", fmt.Errorf("device does not exist")
	}
	return "", nil
}

func (f *fakeRunner) all() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

func (f *fakeRunner) find(substr string) (string, bool) {
	for _, call := range f.all() {
		if strings.Contains(call, substr) {
			return call, true
		}
	}
	return "", false
}

func newNativePlugin(t *testing.T, runner cmdRunner, probe func(context.Context, string) bool) *FakeIPNatPlugin {
	t.Helper()
	p := newTestPlugin(t, "198.18.0.0/16")
	p.runner = runner
	p.probe = probe
	return p
}

func TestArgsDecodeUseTun(t *testing.T) {
	var args Args
	if err := utils.WeakDecode(map[string]interface{}{
		"use_tun":           true,
		"route_table":       "oversea",
		"route_aggregation": false,
	}, &args); err != nil {
		t.Fatalf("decode args failed: %v", err)
	}
	if !args.UseTun || args.RouteTable != "oversea" {
		t.Fatalf("unexpected decode result: %+v", args)
	}
	if args.AggregateRoutes == nil || *args.AggregateRoutes {
		t.Fatalf("route_aggregation = %v, want explicit false", args.AggregateRoutes)
	}
}

func TestInitWithUseTunDoesNotFail(t *testing.T) {
	// The tun data path is prepared at startup; a failed device setup must only
	// warn, because the DNS side still has to serve queries.
	bp := coremain.NewBP("test_fakeip", PluginType, zap.NewNop(), nil)
	plugin, err := Init(bp, &Args{
		DBPath:      filepath.Join(t.TempDir(), "fakeip.db"),
		TablePrefix: "test",
		IPv4Range:   "198.18.0.0/16",
		UseTun:      true,
		TunDev:      "tun9",
	})
	if err != nil {
		t.Fatalf("Init with use_tun failed: %v", err)
	}
	fp := plugin.(*FakeIPNatPlugin)
	t.Cleanup(func() { _ = fp.Close() })
	if fp.tunDev != "tun9" {
		t.Fatalf("tunDev = %q, want tun9", fp.tunDev)
	}

	// The deprecated script field must not prevent startup either.
	bp = coremain.NewBP("test_fakeip", PluginType, zap.NewNop(), nil)
	deprecated, err := Init(bp, &Args{
		DBPath:      filepath.Join(t.TempDir(), "fakeip.db"),
		TablePrefix: "test",
		IPv4Range:   "198.18.0.0/16",
		Script:      "/config/mosdns/nat_map.sh",
	})
	if err != nil {
		t.Fatalf("Init with deprecated script failed: %v", err)
	}
	_ = deprecated.(*FakeIPNatPlugin).Close()
}

func TestParseCandidateIPs(t *testing.T) {
	got := parseCandidateIPs(" 1.2.3.4, 1.2.3.4 ,5.6.7.8,10.0.0.999,::1,,")
	want := []string{"1.2.3.4", "5.6.7.8"}
	if len(got) != len(want) {
		t.Fatalf("parseCandidateIPs = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("parseCandidateIPs = %v, want %v", got, want)
		}
	}
	if parseCandidateIPs("  ") != nil {
		t.Fatal("blank input should yield no candidates")
	}
}

func TestParseNFTMappings(t *testing.T) {
	out := `table ip fakeip_test {
	map dnat_map {
		type ipv4_addr : ipv4_addr
		elements = {
			198.18.0.1 : 1.2.3.4,
			198.18.0.2 : 5.6.7.8
		}
	}
}`
	got := parseNFTMappings(out)
	if len(got) != 2 || got["198.18.0.1"] != "1.2.3.4" || got["198.18.0.2"] != "5.6.7.8" {
		t.Fatalf("parseNFTMappings = %v", got)
	}
}

func TestCollapsePrefixes(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{
			name: "adjacent /32 merge into /31",
			in:   []string{"1.0.0.3/32", "1.0.0.2/32"},
			want: []string{"1.0.0.2/31"},
		},
		{
			name: "four aligned /32 merge into /30",
			in:   []string{"1.0.0.2/32", "1.0.0.1/32", "1.0.0.3/32", "1.0.0.0/32"},
			want: []string{"1.0.0.0/30"},
		},
		{
			name: "non adjacent stays split",
			in:   []string{"1.0.0.1/32", "1.0.0.3/32"},
			want: []string{"1.0.0.1/32", "1.0.0.3/32"},
		},
		{
			name: "two /31 merge into /30",
			in:   []string{"1.0.0.2/31", "1.0.0.0/31"},
			want: []string{"1.0.0.0/30"},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			prefixes := mustParsePrefixes(t, c.in)
			got := collapsePrefixes(prefixes)
			if len(got) != len(c.want) {
				t.Fatalf("collapse %v = %v, want %v", c.in, got, c.want)
			}
			for i := range c.want {
				if got[i].String() != c.want[i] {
					t.Fatalf("collapse %v = %v, want %v", c.in, got, c.want)
				}
			}
		})
	}
}

func mustParsePrefixes(t *testing.T, in []string) []netip.Prefix {
	t.Helper()
	out := make([]netip.Prefix, 0, len(in))
	for _, s := range in {
		prefix, err := netip.ParsePrefix(s)
		if err != nil {
			t.Fatalf("bad test prefix %q: %v", s, err)
		}
		out = append(out, prefix)
	}
	return out
}

func TestEnsureNFTTableCreatesOnce(t *testing.T) {
	runner := &fakeRunner{tableExists: false}
	p := newNativePlugin(t, runner, func(context.Context, string) bool { return true })

	if err := p.ensureNFTTable(context.Background(), "fakeip_test", "eth0"); err != nil {
		t.Fatalf("ensureNFTTable failed: %v", err)
	}
	for _, want := range []string{
		"nft add table ip fakeip_test",
		"nft add map ip fakeip_test dnat_map",
		"nft add rule ip fakeip_test prerouting ip daddr 198.18.0.0/16 dnat to ip daddr map @dnat_map",
		"nft add rule ip fakeip_test forward ip daddr 198.18.0.0/16 drop",
		"nft add rule ip fakeip_test postrouting ct status dnat masquerade",
	} {
		if _, ok := runner.find(want); !ok {
			t.Fatalf("missing command %q in %v", want, runner.all())
		}
	}

	// An existing table must be reused as-is.
	runner.tableExists = true
	runner.calls = nil
	if err := p.ensureNFTTable(context.Background(), "fakeip_test", "eth0"); err != nil {
		t.Fatalf("ensureNFTTable on existing table failed: %v", err)
	}
	if _, ok := runner.find("nft add"); ok {
		t.Fatalf("existing table must not be recreated: %v", runner.all())
	}
}

func TestSyncNATKeepsReachableMapping(t *testing.T) {
	runner := &fakeRunner{
		tableExists: true,
		mappings:    "198.18.0.1 : 1.2.3.4",
	}
	p := newNativePlugin(t, runner, func(_ context.Context, ip string) bool { return ip == "1.2.3.4" })

	p.syncNAT(context.Background(), "198.18.0.1", "example.com", "9.9.9.9")

	if _, ok := runner.find("nft add element"); ok {
		t.Fatalf("reachable mapping must be kept, commands: %v", runner.all())
	}
	if countRouteCalls(runner.all(), "1.2.3.4", false) == 0 {
		t.Fatalf("host route for the kept mapping missing: %v", runner.all())
	}
}

func TestSyncNATSelectsReachableCandidate(t *testing.T) {
	runner := &fakeRunner{tableExists: true}
	p := newNativePlugin(t, runner, func(_ context.Context, ip string) bool { return ip == "2.2.2.2" })

	p.syncNAT(context.Background(), "198.18.0.1", "example.com", "1.1.1.1,2.2.2.2")

	call, ok := runner.find("nft add element")
	if !ok {
		t.Fatalf("mapping was not written: %v", runner.all())
	}
	if call != "nft add element ip fakeip_test dnat_map { 198.18.0.1 : 2.2.2.2 }" {
		t.Fatalf("unexpected mapping command: %s", call)
	}
	if countRouteCalls(runner.all(), "2.2.2.2", false) == 0 {
		t.Fatalf("host route for the selected ip missing: %v", runner.all())
	}
}

func TestSyncNATFallsBackToFirstCandidate(t *testing.T) {
	runner := &fakeRunner{tableExists: true}
	p := newNativePlugin(t, runner, func(context.Context, string) bool { return false })

	p.syncNAT(context.Background(), "198.18.0.1", "example.com", "1.1.1.1,2.2.2.2")

	call, ok := runner.find("nft add element")
	if !ok {
		t.Fatalf("mapping was not written: %v", runner.all())
	}
	if call != "nft add element ip fakeip_test dnat_map { 198.18.0.1 : 1.1.1.1 }" {
		t.Fatalf("unexpected fallback command: %s", call)
	}
}

func TestSyncNATUsesDBCandidates(t *testing.T) {
	runner := &fakeRunner{tableExists: true}
	p := newNativePlugin(t, runner, func(_ context.Context, ip string) bool { return ip == "5.6.7.8" })

	ctx := context.Background()
	// The newest row must be tried first when the answer carries no ip.
	if err := p.upsertRealIPs(ctx, "example.com", []string{"1.2.3.4"}, 100); err != nil {
		t.Fatalf("seed old ip failed: %v", err)
	}
	if err := p.upsertRealIPs(ctx, "example.com", []string{"5.6.7.8"}, 200); err != nil {
		t.Fatalf("seed new ip failed: %v", err)
	}

	p.syncNAT(ctx, "198.18.0.1", "example.com", "")

	call, ok := runner.find("nft add element")
	if !ok {
		t.Fatalf("mapping was not written: %v", runner.all())
	}
	if call != "nft add element ip fakeip_test dnat_map { 198.18.0.1 : 5.6.7.8 }" {
		t.Fatalf("unexpected db candidate command: %s", call)
	}
}

func TestAggregateManagedRoutes(t *testing.T) {
	// Two adjacent /32 host routes steer traffic to the same gateway. The scan
	// must install the /31 first and only then delete the originals.
	runner := &fakeRunner{}
	p := newNativePlugin(t, runner, func(context.Context, string) bool { return true })

	p.collapseManagedRoutes(context.Background(),
		[]string{"1.2.3.4/32", "1.2.3.5/32"}, "10.0.0.1", "eth0")

	calls := runner.all()
	addIdx, delIdx := -1, -1
	for i, call := range calls {
		if strings.Contains(call, "1.2.3.4") && !strings.Contains(call, "delete") && addIdx < 0 {
			addIdx = i
		}
		if strings.Contains(call, "1.2.3.4") && strings.Contains(call, "delete") && delIdx < 0 {
			delIdx = i
		}
	}
	if addIdx < 0 {
		t.Fatalf("aggregated route missing: %v", calls)
	}
	if delIdx < 0 {
		t.Fatalf("old host route not deleted: %v", calls)
	}
	if addIdx > delIdx {
		t.Fatalf("routes were deleted before the aggregate was installed: %v", calls)
	}
	if countRouteCalls(calls, "1.2.3.5", true) == 0 {
		t.Fatalf("second host route not deleted: %v", calls)
	}
}

func TestSyncNATSkipsWhenNFTFails(t *testing.T) {
	runner := &fakeRunner{tableExists: false, failContains: "nft add table"}
	p := newNativePlugin(t, runner, func(context.Context, string) bool { return true })

	p.syncNAT(context.Background(), "198.18.0.1", "example.com", "1.1.1.1")

	if _, ok := runner.find("nft add element"); ok {
		t.Fatalf("must not write an element without a table: %v", runner.all())
	}
	if _, ok := runner.find("ip route replace"); ok {
		t.Fatalf("must not leave host routes behind when the table failed: %v", runner.all())
	}
}

func TestDeleteManagedRoutes(t *testing.T) {
	runner := &fakeRunner{}
	p := newNativePlugin(t, runner, func(context.Context, string) bool { return true })

	deleted := p.deleteManagedRoutes(context.Background(), []string{"1.2.3.4/32", "1.2.3.4/30"})
	if deleted != 2 {
		t.Fatalf("deleted = %d, want 2", deleted)
	}
	for _, prefix := range []string{"1.2.3.4/32", "1.2.3.4/30"} {
		if countRouteCalls(runner.all(), prefix, true) == 0 {
			t.Fatalf("route %s was not removed: %v", prefix, runner.all())
		}
	}
}

func TestCleanupDataPathDropsNFTTable(t *testing.T) {
	runner := &fakeRunner{tableExists: true}
	p := newNativePlugin(t, runner, func(context.Context, string) bool { return true })

	p.cleanupDataPath()

	if _, ok := runner.find("nft delete table ip fakeip_test"); !ok {
		t.Fatalf("nft table was not removed on shutdown: %v", runner.all())
	}
}

func TestEnsureNFTTableAddsMSSClamp(t *testing.T) {
	runner := &fakeRunner{tableExists: false}
	p := newNativePlugin(t, runner, func(context.Context, string) bool { return true })
	p.mssClamp = 1360

	if err := p.ensureNFTTable(context.Background(), p.nftTableName(), "eth0"); err != nil {
		t.Fatalf("ensureNFTTable: %v", err)
	}

	// Both the client SYN and the server SYN-ACK have to be clamped, otherwise
	// one direction keeps advertising the full Ethernet MSS.
	count := 0
	for _, call := range runner.all() {
		if strings.Contains(call, "tcp option maxseg size set 1360") {
			count++
		}
	}
	if count != 2 {
		t.Fatalf("mss clamp rules = %d, want 2, calls: %v", count, runner.all())
	}
	if !strings.Contains(strings.Join(runner.all(), "\n"), "hook prerouting priority mangle") {
		t.Fatalf("mss clamp chain missing: %v", runner.all())
	}
}

// TestCleanupDropsStaleNFTTableInTunMode pins the mode-switch case: the tun
// path installs no nft table, so one that exists was left by a non-tun run and
// its DNAT chain keeps rewriting destinations in prerouting. Both the shutdown
// path and the startup helper have to remove it.
func TestCleanupDropsStaleNFTTableInTunMode(t *testing.T) {
	runner := &fakeRunner{tableExists: true}
	p := newNativePlugin(t, runner, func(context.Context, string) bool { return true })
	p.useTun = true

	p.cleanupStaleNFTTable(context.Background())
	if _, ok := runner.find("nft delete table ip fakeip_test"); !ok {
		t.Fatalf("startup did not remove the stale table: %v", runner.all())
	}

	runner2 := &fakeRunner{tableExists: true}
	p2 := newNativePlugin(t, runner2, func(context.Context, string) bool { return true })
	p2.useTun = true
	p2.cleanupDataPath()
	if _, ok := runner2.find("nft delete table ip fakeip_test"); !ok {
		t.Fatalf("shutdown did not remove the stale table: %v", runner2.all())
	}
}

// TestCleanupStaleNFTTableToleratesAbsence checks the normal tun start: there is
// no table to delete, and that must not surface as an error or a panic.
func TestCleanupStaleNFTTableToleratesAbsence(t *testing.T) {
	runner := &fakeRunner{failContains: "nft delete table"}
	p := newNativePlugin(t, runner, func(context.Context, string) bool { return true })
	p.useTun = true

	p.cleanupStaleNFTTable(context.Background())
	if _, ok := runner.find("nft delete table ip fakeip_test"); !ok {
		t.Fatalf("the absence probe was not attempted: %v", runner.all())
	}
}
