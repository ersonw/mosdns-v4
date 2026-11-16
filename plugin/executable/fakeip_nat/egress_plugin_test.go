package fakeipnat

// The egress outlets themselves are tested in pkg/egress. What remains here
// tests how this plugin wires them: which link it accepts, what it does when
// there is no tun, and that a fake answer keeps its domain.

import (
	"net/netip"
	"path/filepath"
	"testing"

	"github.com/ersonw/mosdns-v4/coremain"
	"github.com/ersonw/mosdns-v4/pkg/egress"
	"github.com/ersonw/mosdns-v4/pkg/utils"
	"go.uber.org/zap"
)

func TestArgsDecodeProxy(t *testing.T) {
	var args Args
	if err := utils.WeakDecode(map[string]interface{}{
		"tun_dev":        "tun9",
		"proxy":          "socks5://user:pass@127.0.0.1:1080",
		"proxy_insecure": true,
	}, &args); err != nil {
		t.Fatalf("decode args failed: %v", err)
	}
	if args.TunDev != "tun9" || args.Proxy != "socks5://user:pass@127.0.0.1:1080" || !args.ProxyInsecure {
		t.Fatalf("unexpected decode result: %+v", args)
	}
}

func TestInitRejectsUnsupportedProxyScheme(t *testing.T) {
	bp := coremain.NewBP("test_fakeip", PluginType, zap.NewNop(), nil)
	_, err := Init(bp, &Args{
		DBPath:      filepath.Join(t.TempDir(), "fakeip.db"),
		TablePrefix: "test",
		IPv4Range:   "198.18.0.0/16",
		Proxy:       "ss://YWVzOnB3@host:8388",
	})
	if err == nil {
		t.Fatal("an unsupported proxy scheme should fail startup")
	}
}

func TestInitWithoutTunKeepsDirectEgress(t *testing.T) {
	bp := coremain.NewBP("test_fakeip", PluginType, zap.NewNop(), nil)
	plugin, err := Init(bp, &Args{
		DBPath:      filepath.Join(t.TempDir(), "fakeip.db"),
		TablePrefix: "test",
		IPv4Range:   "198.18.0.0/16",
		Proxy:       "socks5://127.0.0.1:1",
	})
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	fp := plugin.(*FakeIPNatPlugin)
	t.Cleanup(func() { _ = fp.Close() })

	// use_tun is false, so the proxy must not be dialed at startup.
	if _, ok := fp.egress.(*egress.Direct); !ok {
		t.Fatalf("egress = %T, want *egress.Direct while use_tun is false", fp.egress)
	}
}

// A socks5 link resolves the target with the host resolver. When that answer is
// one of the plugin's own fake addresses, the domain must survive: the proxy
// would otherwise be told to connect to a host that does not exist, which is
// exactly the "dial tcp 198.18.x.x: i/o timeout" seen on the far side.
func TestChooseProxyTargetKeepsDomainForFakeAnswer(t *testing.T) {
	fake := netip.MustParsePrefix("198.18.0.0/15")
	cases := []struct {
		addr     string
		resolved string
		want     string
	}{
		// The host resolver is this plugin: the answer is a fake ip, so the
		// name has to reach the proxy unchanged.
		{"www.google.com:443", "198.18.0.27:443", "www.google.com:443"},
		{"www.google.com:443", "198.19.11.31:443", "www.google.com:443"},
		// A public answer keeps the old behaviour.
		{"www.google.com:443", "142.250.0.1:443", "142.250.0.1:443"},
		// A failed lookup already keeps the name; it must stay untouched.
		{"unknown.invalid:443", "unknown.invalid:443", "unknown.invalid:443"},
	}
	for _, c := range cases {
		if got := egress.ChooseProxyTarget(c.addr, c.resolved, fake); got != c.want {
			t.Errorf("chooseProxyTarget(%q, %q) = %q, want %q", c.addr, c.resolved, got, c.want)
		}
	}
	if got := egress.ChooseProxyTarget("www.google.com:443", "198.18.0.27:443", netip.Prefix{}); got != "198.18.0.27:443" {
		t.Error("an invalid range must not rewrite the target")
	}
}

func TestFakeAddressInRange(t *testing.T) {
	fake := netip.MustParsePrefix("198.18.0.0/15")
	cases := []struct {
		target string
		want   bool
	}{
		{"198.18.0.27:443", true},
		{"198.19.191.130:443", true},
		{"8.8.8.8:53", false},
		{"www.google.com:443", false},
		{"", false},
	}
	for _, c := range cases {
		if got := egress.FakeAddressInRange(c.target, fake); got != c.want {
			t.Errorf("egress.FakeAddressInRange(%q) = %v, want %v", c.target, got, c.want)
		}
	}
	if egress.FakeAddressInRange("198.18.0.27:443", netip.Prefix{}) {
		t.Error("an invalid range must never claim an address")
	}
}

func TestSetFakeRangeOnlyAppliesToSocks5(t *testing.T) {
	prefix := netip.MustParsePrefix("198.18.0.0/15")
	socks, err := newEgress("socks5://127.0.0.1:1080", false)
	if err != nil {
		t.Fatalf("newEgress failed: %v", err)
	}
	if !setFakeRange(socks, prefix) {
		t.Fatal("socks5 should accept the fake range")
	}
	if !socks.(*egress.Socks5).FakeRange().IsValid() {
		t.Fatal("socks5 outlet did not keep the fake range")
	}
	// The other outlets send the domain unchanged, so they must not claim it.
	for _, link := range []string{"http://127.0.0.1:8080", "trojan://pw@127.0.0.1:443", "https://127.0.0.1:443"} {
		e, err := newEgress(link, false)
		if err != nil {
			t.Fatalf("newEgress(%q) failed: %v", link, err)
		}
		if setFakeRange(e, prefix) {
			t.Errorf("%s must not accept the fake range", link)
		}
	}
}

// A target that lands inside the plugin's own range can only come from a broken
// mapping row; dialing it always times out, so it is refused before an outlet
// sees it.
func TestFakeTargetRejectsOwnRange(t *testing.T) {
	p := &FakeIPNatPlugin{prefix: netip.MustParsePrefix("198.18.0.0/15")}
	cases := []struct {
		target string
		want   bool
	}{
		{"198.18.0.27:443", true},
		{"198.19.0.1:80", true},
		{"8.8.8.8:443", false},
		{"www.google.com:443", false},
		{"", false},
	}
	for _, c := range cases {
		if got := p.fakeTarget(c.target); got != c.want {
			t.Errorf("fakeTarget(%q) = %v, want %v", c.target, got, c.want)
		}
	}
}
