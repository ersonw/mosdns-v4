package fakeipnat

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/ersonw/mosdns-v4/pkg/executable_seq"
	"github.com/ersonw/mosdns-v4/pkg/query_context"
	"github.com/miekg/dns"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

// directV6Plugin is a direct (no proxy) tun instance. ready=false leaves the
// egress checker nil, which is the "cannot tell" state and must behave exactly
// like a host without IPv6.
func directV6Plugin(t *testing.T, ready bool) *FakeIPNatPlugin {
	t.Helper()
	p := newRealIPPlugin(t, false)
	p.useTun = true
	p.proxyActive = false
	if ready {
		p.v6egress = &v6EgressProbe{target: "[2606:4700:4700::1111]:443", probe: dialIPv6Probe}
		p.v6egress.ready.Store(true)
	}
	return p
}

func TestDirectIPv6OnlyDomainGetsFakeIPWhenEgressReady(t *testing.T) {
	p := directV6Plugin(t, true)
	n := &ipv6OnlyNext{hasAAAA: true}
	qCtx := query_context.NewContext(aQuery("ipv6-only.example."), nil)

	if err := p.Exec(context.Background(), qCtx, executable_seq.WrapExecutable(n)); err != nil {
		t.Fatalf("Exec failed: %v", err)
	}
	if n.calls != 2 {
		t.Fatalf("next calls = %d, want the A lookup plus the AAAA probe", n.calls)
	}
	answers := qCtx.R().Answer
	if len(answers) != 1 {
		t.Fatalf("answers = %d, want one fake A record", len(answers))
	}
	a, ok := answers[0].(*dns.A)
	if !ok {
		t.Fatalf("answer type = %T, want *dns.A", answers[0])
	}
	addr, ok := netip.AddrFromSlice(a.A)
	if !ok || !p.prefix.Contains(addr) {
		t.Fatalf("answer %v is outside %s", a.A, p.prefix)
	}
	if got := mappingCount(t, p); got != 1 {
		t.Fatalf("mapping rows = %d, want 1", got)
	}

	// The outlet must be able to dial what the answer recorded, otherwise the
	// client gets a fake address and every connection fails.
	const domain = "ipv6-only.example"
	v6 := p.runtime.v6Of(domain)
	if len(v6) != 1 || v6[0] != "2602:ffe4:c98:2910::2" {
		t.Fatalf("recorded ipv6 addresses = %v, want the AAAA answer", v6)
	}
	var stored string
	if err := p.db.QueryRowContext(context.Background(),
		"SELECT real_ip FROM test_real_ips WHERE domain = ?", domain).Scan(&stored); err != nil {
		t.Fatalf("read stored real ip failed: %v", err)
	}
	if stored != "2602:ffe4:c98:2910::2" {
		t.Fatalf("stored real ip = %q, want the AAAA address", stored)
	}

	real, err := p.outletRealIP(context.Background(), domain)
	if err != nil {
		t.Fatalf("outletRealIP failed: %v", err)
	}
	if !real.Is6() {
		t.Fatalf("outlet destination = %s, want an IPv6 address", real)
	}
}

func TestDirectIPv6OnlyDomainKeepsEmptyAnswerWithoutEgress(t *testing.T) {
	p := directV6Plugin(t, false)
	n := &ipv6OnlyNext{hasAAAA: true}
	qCtx := query_context.NewContext(aQuery("ipv6-only.example."), nil)

	if err := p.Exec(context.Background(), qCtx, executable_seq.WrapExecutable(n)); err != nil {
		t.Fatalf("Exec failed: %v", err)
	}
	// Only the original A lookup: an unusable IPv6 path must not spend a query
	// on an AAAA probe it cannot use.
	if n.calls != 1 {
		t.Fatalf("next calls = %d, want only the A lookup", n.calls)
	}
	if got := len(qCtx.R().Answer); got != 0 {
		t.Fatalf("answers = %d, want the empty answer an IPv4-only host produces", got)
	}
	if got := mappingCount(t, p); got != 0 {
		t.Fatalf("mapping rows = %d, want 0", got)
	}
}

func TestDirectIPv6OnlyDomainWithoutAAAAIsNotAllocated(t *testing.T) {
	p := directV6Plugin(t, true)
	n := &ipv6OnlyNext{hasAAAA: false}
	qCtx := query_context.NewContext(aQuery("no-aaaa.example."), nil)

	if err := p.Exec(context.Background(), qCtx, executable_seq.WrapExecutable(n)); err != nil {
		t.Fatalf("Exec failed: %v", err)
	}
	if got := len(qCtx.R().Answer); got != 0 {
		t.Fatalf("answers = %d, want no fake A record", got)
	}
	if got := mappingCount(t, p); got != 0 {
		t.Fatalf("mapping rows = %d, want 0", got)
	}
}

func TestOutletRealIPPrefersIPv4(t *testing.T) {
	p := directV6Plugin(t, true)
	const domain = "dual.example"
	p.runtime.putReal(domain, []string{"2602:ffe4:c98:2910::2", "203.0.113.9"})

	addr, err := p.outletRealIP(context.Background(), domain)
	if err != nil {
		t.Fatalf("outletRealIP failed: %v", err)
	}
	if !addr.Is4() {
		t.Fatalf("outlet destination = %s, want the recorded IPv4 to keep winning", addr)
	}
}

func TestOutletRealIPRejectsIPv6WithoutEgress(t *testing.T) {
	p := directV6Plugin(t, true)
	const domain = "v6only.example"
	p.runtime.putReal(domain, []string{"2602:ffe4:c98:2910::2"})

	// Egress present: the recorded address is usable.
	if addr, err := p.outletRealIP(context.Background(), domain); err != nil || !addr.Is6() {
		t.Fatalf("outletRealIP = %v, %v; want the IPv6 address", addr, err)
	}
	// Egress gone: the same row must not be handed to a socket that cannot dial it.
	p.v6egress.ready.Store(false)
	if _, err := p.outletRealIP(context.Background(), domain); !errors.Is(err, errNoRealIP) {
		t.Fatalf("outletRealIP error = %v, want errNoRealIP once IPv6 egress is unusable", err)
	}
}

func TestProbeKeepsReadyStateInStep(t *testing.T) {
	v := &v6EgressProbe{target: "probe.test:443", probe: dialIPv6Probe}
	if v.Ready() {
		t.Fatal("a fresh probe must not report a usable egress")
	}
	v.probe = func(context.Context, string) error { return nil }
	v.check(context.Background(), zap.NewNop())
	if !v.Ready() {
		t.Fatal("a successful probe must report a usable egress")
	}
	v.probe = func(context.Context, string) error { return errors.New("no route to host") }
	v.check(context.Background(), zap.NewNop())
	if v.Ready() {
		t.Fatal("a failed probe must fall back to the empty answer")
	}
	// A nil checker is the "probing off" state and must never report ready.
	var off *v6EgressProbe
	if off.Ready() {
		t.Fatal("a nil checker must never be ready")
	}
}

func TestParseIPv6ProbeInterval(t *testing.T) {
	cases := []struct {
		raw  string
		want string
		bad  bool
	}{
		{raw: "", want: "5m0s"},
		{raw: "0", want: "0s"},
		{raw: "90s", want: "1m30s"},
		{raw: "bogus", bad: true},
		{raw: "-5m", bad: true},
	}
	for _, c := range cases {
		got, err := parseIPv6ProbeInterval(c.raw)
		if c.bad {
			if err == nil {
				t.Fatalf("parseIPv6ProbeInterval(%q) = %v, want an error", c.raw, got)
			}
			continue
		}
		if err != nil {
			t.Fatalf("parseIPv6ProbeInterval(%q) failed: %v", c.raw, err)
		}
		if got.String() != c.want {
			t.Fatalf("parseIPv6ProbeInterval(%q) = %v, want %s", c.raw, got, c.want)
		}
	}
}

func TestIsIPv6Target(t *testing.T) {
	cases := []struct {
		addr string
		want bool
	}{
		{addr: "[2602:ffe4:c98:2910::2]:443", want: true},
		{addr: "2602:ffe4:c98:2910::2", want: true},
		{addr: "203.0.113.9:443", want: false},
		{addr: "example.com:443", want: false},
	}
	for _, c := range cases {
		if got := isIPv6Target(c.addr); got != c.want {
			t.Fatalf("isIPv6Target(%q) = %v, want %v", c.addr, got, c.want)
		}
	}
}

// TestArgsAcceptIPv6ProbeKeys pins the YAML spelling: a typo here fails silently
// at startup and the plugin just keeps the empty answer.
func TestArgsAcceptIPv6ProbeKeys(t *testing.T) {
	const raw = "ipv6_egress: auto\nipv6_probe: \"[2606:4700:4700::1111]:443\"\nipv6_probe_interval: \"5m\"\n"
	var a Args
	if err := yaml.Unmarshal([]byte(raw), &a); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if a.IPv6Egress != "auto" {
		t.Fatalf("ipv6_egress = %q", a.IPv6Egress)
	}
	if a.IPv6Probe != "[2606:4700:4700::1111]:443" {
		t.Fatalf("ipv6_probe = %q", a.IPv6Probe)
	}
	if a.IPv6ProbeInterval != "5m" {
		t.Fatalf("ipv6_probe_interval = %q", a.IPv6ProbeInterval)
	}
}
