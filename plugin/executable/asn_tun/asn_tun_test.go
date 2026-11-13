package asn_tun

import (
	"context"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ersonw/mosdns-v4/coremain"
	"github.com/ersonw/mosdns-v4/pkg/data_provider"
	"go.uber.org/zap"
)

func TestParsePrefixLinesSkipsCommentsAndTinyBlocks(t *testing.T) {
	body := `
# AS4134
1.2.3.0/24
1.2.3.0/24
5.6.0.0/16 # inline comment
10.0.0.0/7
2001:db8::/32
bad-line
`
	got, err := parsePrefixLines(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("prefixes = %v, want two IPv4 prefixes", got)
	}
	if got[0].String() != "1.2.3.0/24" || got[1].String() != "5.6.0.0/16" {
		t.Fatalf("prefixes = %v", got)
	}
}

func TestNftFileContainsIntervalSetAndBypass(t *testing.T) {
	text := nftFile("asn_tun", 291, []netip.Prefix{
		netip.MustParsePrefix("1.2.3.0/24"),
		netip.MustParsePrefix("5.6.0.0/16"),
	}, []netip.Addr{
		netip.MustParseAddr("8.8.8.8"),
	}, nil, "")
	for _, want := range []string{
		"add table inet asn_tun",
		"type ipv4_addr; flags interval",
		"add rule inet asn_tun mark_pre meta mark 0 ip daddr != @bypass4 ip daddr @asn4 meta mark set 291",
		"add rule inet asn_tun mark_out meta mark 0 ip daddr != @bypass4 ip daddr @asn4 meta mark set 291",
		"add element inet asn_tun asn4 { 1.2.3.0/24, 5.6.0.0/16 }",
		"add element inet asn_tun bypass4 { 8.8.8.8 }",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("nft file missing %q:\n%s", want, text)
		}
	}
}

func TestNftFileMirrorDevRestrictsIngress(t *testing.T) {
	text := nftFile("asn_tun", 291, []netip.Prefix{
		netip.MustParsePrefix("1.2.3.0/24"),
	}, []netip.Addr{
		netip.MustParseAddr("8.8.8.8"),
	}, nil, "mirror0")
	for _, want := range []string{
		`add rule inet asn_tun mark_pre iifname "mirror0" meta mark 0 ip daddr != @bypass4 ip daddr @asn4 meta mark set 291`,
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("nft file missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "mark_out") {
		t.Fatalf("mirror mode must not install the output mark chain:\n%s", text)
	}
}

func TestLoadSkipPrefixesProvider(t *testing.T) {
	path := filepath.Join(t.TempDir(), "skip_ip.txt")
	if err := os.WriteFile(path, []byte("10.0.0.0/8\n192.168.0.0/16\n2001:db8::/32\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dp, err := data_provider.NewDataProvider(zap.NewNop(), &data_provider.DataProviderConfig{
		Tag:  "test_skip",
		File: path,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer dp.Close()
	dm := data_provider.NewDataManager()
	dm.AddDataProvider("test_skip", dp)

	got, err := loadSkipPrefixesWithManager(dm, []string{"provider:test_skip"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("prefixes = %v, want two IPv4 prefixes", got)
	}
	if got[0].String() != "10.0.0.0/8" || got[1].String() != "192.168.0.0/16" {
		t.Fatalf("prefixes = %v", got)
	}
}

func TestPrefixCacheRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "asn_tun_prefixes.json")
	want := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("192.168.0.0/16"),
	}
	if err := writePrefixCache(path, []uint32{112, 4134}, want); err != nil {
		t.Fatal(err)
	}
	got, err := readPrefixCache(path, []uint32{4134, 112})
	if err != nil {
		t.Fatal(err)
	}
	if !prefixesEqual(got, want) {
		t.Fatalf("cache prefixes = %v", got)
	}
	if prefixesEqual(got, []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
	}) {
		t.Fatal("different prefix sets should compare unequal")
	}
}

func TestFetchPrefixesBGpq3(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not available")
	}
	dir := t.TempDir()
	fetchPath := filepath.Join(dir, "fetch.py")
	mergePath := filepath.Join(dir, "merge.py")
	if err := os.WriteFile(fetchPath, []byte(
		"import sys\n"+
			"open(sys.argv[2], 'w').write('1.2.3.0/24\\n10.0.0.0/8\\n')\n",
	), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mergePath, []byte(
		"import sys\n"+
			"for line in sys.stdin:\n"+
			"    line = line.strip()\n"+
			"    if line:\n"+
			"        print(line)\n",
	), 0o600); err != nil {
		t.Fatal(err)
	}

	p := &ASNTunPlugin{
		asns: []uint32{112},
		args: Args{Python: "python3", FetchScript: fetchPath, MergeScript: mergePath},
	}
	got, err := p.fetchPrefixesBGpq3(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !prefixesEqual(got, []netip.Prefix{
		netip.MustParsePrefix("1.2.3.0/24"),
		netip.MustParsePrefix("10.0.0.0/8"),
	}) {
		t.Fatalf("prefixes = %v", got)
	}
}

func TestLoadSkipPrefixesDirectEntries(t *testing.T) {
	bp := coremain.NewBP("asn", PluginType, zap.NewNop(), nil)
	got, err := loadSkipPrefixes(bp, []string{
		"10.0.0.0/8",
		"10.1.0.0/16",
		"2001:db8::/32",
		"192.168.0.0/16",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("prefixes = %v, want merged IPv4 prefixes only", got)
	}
	if got[0].String() != "10.0.0.0/8" || got[1].String() != "192.168.0.0/16" {
		t.Fatalf("prefixes = %v", got)
	}
}

func TestNftFileSkipsDestinationPrefixes(t *testing.T) {
	text := nftFile("asn_tun", 291, []netip.Prefix{
		netip.MustParsePrefix("1.2.3.0/24"),
	}, []netip.Addr{
		netip.MustParseAddr("8.8.8.8"),
	}, []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("192.168.0.0/16"),
	}, "")
	for _, want := range []string{
		"add set inet asn_tun skip4 { type ipv4_addr; flags interval; }",
		"add rule inet asn_tun mark_pre meta mark 0 ip daddr != @bypass4 ip daddr != @skip4 ip daddr @asn4 meta mark set 291",
		"add element inet asn_tun skip4 { 10.0.0.0/8, 192.168.0.0/16 }",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("nft file missing %q:\n%s", want, text)
		}
	}
}

func TestNewPluginMirrorDevValidation(t *testing.T) {
	bp := coremain.NewBP("asn", PluginType, zap.NewNop(), nil)
	p, err := newPlugin(bp, &Args{
		ASN:        []uint32{4134},
		NextHop:    "10.0.0.1",
		NextHopDev: "eth0",
		MirrorDev:  "mirror0",
	})
	if err != nil {
		t.Fatal(err)
	}
	if p.mirrorDev != "mirror0" {
		t.Fatalf("mirror dev = %q", p.mirrorDev)
	}
	if _, err := newPlugin(bp, &Args{
		ASN:        []uint32{4134},
		NextHop:    "10.0.0.1",
		NextHopDev: "eth0",
		MirrorDev:  `bad"dev`,
	}); err == nil {
		t.Fatal("invalid mirror dev should be rejected")
	}
}

func TestNewPluginDefaults(t *testing.T) {
	bp := coremain.NewBP("asn", PluginType, zap.NewNop(), nil)
	p, err := newPlugin(bp, &Args{
		ASN:        []uint32{4134},
		NextHop:    "10.0.0.1",
		NextHopDev: "eth0",
	})
	if err != nil {
		t.Fatal(err)
	}
	if p.args.NftTable != "asn_tun" || p.routeTable != "123" {
		t.Fatalf("defaults: nft=%q route=%q", p.args.NftTable, p.routeTable)
	}
	if p.mark != 123 || p.egressMark != 124 {
		t.Fatalf("marks: %d/%d", p.mark, p.egressMark)
	}
	if p.tunAddr.String() != "192.0.2.1" {
		t.Fatalf("tun addr = %s", p.tunAddr)
	}
	if p.args.Source != "ipverse" || p.args.Cache != defaultCache {
		t.Fatalf("prefix defaults: source=%q cache=%q", p.args.Source, p.args.Cache)
	}
}

func TestNewPluginAcceptsBGpq3Source(t *testing.T) {
	bp := coremain.NewBP("asn", PluginType, zap.NewNop(), nil)
	p, err := newPlugin(bp, &Args{
		ASN:        []uint32{4134},
		Source:     "bgpq3",
		NextHop:    "10.0.0.1",
		NextHopDev: "eth0",
	})
	if err != nil {
		t.Fatal(err)
	}
	if p.args.Source != "bgpq3" ||
		filepath.Base(p.args.FetchScript) != defaultFetchScript ||
		filepath.Base(p.args.MergeScript) != defaultMergeScript ||
		p.args.Python != defaultPython {
		t.Fatalf("bgpq3 defaults: source=%q fetch=%q merge=%q python=%q",
			p.args.Source, p.args.FetchScript, p.args.MergeScript, p.args.Python)
	}
}

func TestNewPluginRejectsMainRouteTable(t *testing.T) {
	bp := coremain.NewBP("asn", PluginType, zap.NewNop(), nil)
	_, err := newPlugin(bp, &Args{
		ASN:        []uint32{4134},
		NextHop:    "10.0.0.1",
		RouteTable: "main",
	})
	if err == nil {
		t.Fatal("main route table should be rejected")
	}
}

func TestNormalizePrefixesRemovesOverlaps(t *testing.T) {
	in := []netip.Prefix{
		netip.MustParsePrefix("91.108.56.0/23"),
		netip.MustParsePrefix("149.154.168.0/22"),
		netip.MustParsePrefix("91.108.56.0/22"),
		netip.MustParsePrefix("91.108.56.0/22"),
		netip.MustParsePrefix("91.108.4.0/22"),
	}
	out := normalizePrefixes(in)
	want := []netip.Prefix{
		netip.MustParsePrefix("91.108.4.0/22"),
		netip.MustParsePrefix("91.108.56.0/22"),
		netip.MustParsePrefix("149.154.168.0/22"),
	}
	if !prefixesEqual(out, want) {
		t.Fatalf("normalized = %v, want %v", out, want)
	}
}

func TestPolicyRuleUsesDistinctMarks(t *testing.T) {
	p := &ASNTunPlugin{mark: 123, routeTable: "123", egressMark: 124, egressTable: "124", rulePrio: 1000}
	if got := strings.Join(p.ingressRuleArgs("add"), " "); got != "rule add fwmark 123 lookup 123 prio 1000" {
		t.Fatalf("ingress rule = %q", got)
	}
	if got := strings.Join(p.egressRuleArgs("add"), " "); got != "rule add fwmark 124 lookup 124 prio 1001" {
		t.Fatalf("egress rule = %q", got)
	}
}

type recordingRunner struct {
	calls []string
}

func (r *recordingRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	r.calls = append(r.calls, strings.Join(append([]string{name}, args...), " "))
	return "", nil
}

func TestCloseCleansRoutesAndNft(t *testing.T) {
	bp := coremain.NewBP("asn", PluginType, zap.NewNop(), nil)
	runner := new(recordingRunner)
	p := &ASNTunPlugin{
		BP:            bp,
		runner:        runner,
		args:          Args{NftTable: "asn_tun"},
		mark:          123,
		routeTable:    "123",
		egressMark:    124,
		egressTable:   "124",
		rulePrio:      1000,
		nftInstalled:  true,
		routesStarted: true,
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"ip rule del fwmark 123 lookup 123 prio 1000",
		"ip rule del fwmark 124 lookup 124 prio 1001",
		"ip route del default table 123",
		"ip route del default table 124",
		"nft delete table inet asn_tun",
	}
	if len(runner.calls) != len(want) {
		t.Fatalf("calls = %v", runner.calls)
	}
	for i := range want {
		if runner.calls[i] != want[i] {
			t.Fatalf("call %d = %q, want %q", i, runner.calls[i], want[i])
		}
	}

	// Close is idempotent and must not repeat system changes.
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) != len(want) {
		t.Fatalf("second Close issued more calls: %v", runner.calls)
	}
}
