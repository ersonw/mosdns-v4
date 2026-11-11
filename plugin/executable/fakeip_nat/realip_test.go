package fakeipnat

import (
	"context"
	"net"
	"net/netip"
	"path/filepath"
	"testing"

	"github.com/ersonw/mosdns-v4/coremain"
	"github.com/ersonw/mosdns-v4/pkg/query_context"
	"github.com/miekg/dns"
	"go.uber.org/zap"
)

// newRealIPPlugin builds a plugin whose data plane is a recording runner, so a
// test can assert on the routes it would have installed.
func newRealIPPlugin(t *testing.T, realIP bool) *FakeIPNatPlugin {
	t.Helper()
	bp := coremain.NewBP("test_realip", PluginType, zap.NewNop(), nil)
	p0, err := Init(bp, &Args{
		DBPath:      filepath.Join(t.TempDir(), "fakeip.db"),
		TablePrefix: "test",
		IPv4Range:   "198.18.0.0/16",
		RecordTTL:   "0",
		NextHop:     "11.10.12.1",
		NextHopDev:  "wg0",
		RealIP:      realIP,
	})
	if err != nil {
		t.Fatalf("Init(realip=%v) failed: %v", realIP, err)
	}
	p := p0.(*FakeIPNatPlugin)
	p.runner = &fakeRunner{}
	p.probe = func(context.Context, string) bool { return true }
	t.Cleanup(func() { _ = p.Close() })
	return p
}

func aQuery(name string) *dns.Msg {
	q := new(dns.Msg)
	q.SetQuestion(name, dns.TypeA)
	return q
}

func realAnswer(name string, ips ...string) *dns.Msg {
	q := aQuery(name)
	r := new(dns.Msg)
	r.SetReply(q)
	for _, ip := range ips {
		r.Answer = append(r.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP(ip).To4(),
		})
	}
	return r
}

func TestRealIPModeKeepsRealAnswers(t *testing.T) {
	p := newRealIPPlugin(t, true)

	qCtx := query_context.NewContext(aQuery("dns.google."), nil)
	fixed := realAnswer("dns.google.", "1.2.3.4", "5.6.7.8")
	qCtx.SetResponse(fixed)

	if err := p.Exec(context.Background(), qCtx, nil); err != nil {
		t.Fatalf("Exec failed: %v", err)
	}
	if qCtx.R() != fixed {
		t.Fatal("realip mode replaced the response")
	}
	got := qCtx.R().Answer[0].(*dns.A).A.String()
	if got != "1.2.3.4" {
		t.Fatalf("answer = %s, want the real ip 1.2.3.4", got)
	}

	var count int
	if err := p.db.QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM test_mapping").Scan(&count); err != nil {
		t.Fatalf("count mapping failed: %v", err)
	}
	if count != 0 {
		t.Fatalf("realip mode allocated %d fake ips, want 0", count)
	}
}

func TestFakeIPModeAnswersFakeIP(t *testing.T) {
	p := newRealIPPlugin(t, false)

	qCtx := query_context.NewContext(aQuery("dns.google."), nil)
	qCtx.SetResponse(realAnswer("dns.google.", "1.2.3.4"))

	if err := p.Exec(context.Background(), qCtx, nil); err != nil {
		t.Fatalf("Exec failed: %v", err)
	}
	answers := qCtx.R().Answer
	if len(answers) != 1 {
		t.Fatalf("answers = %d, want 1 fake ip", len(answers))
	}
	a, ok := answers[0].(*dns.A)
	if !ok {
		t.Fatalf("answer type = %T, want *dns.A", answers[0])
	}
	addr, ok := netip.AddrFromSlice(a.A)
	if !ok {
		t.Fatalf("fake ip is not a valid address: %x", a.A)
	}
	if !p.prefix.Contains(addr) {
		t.Fatalf("answer %s is outside %s", addr, p.prefix)
	}
}

func TestRealIPRoutesUseDebouncedAggregation(t *testing.T) {
	p := newRealIPPlugin(t, true)
	// The debounce timer would fire during the test; drive aggregation by hand
	// so the assertions stay deterministic.
	p.aggregateRoutes = false
	fr := p.runner.(*fakeRunner)

	p.syncRealRoutes(context.Background(), []string{"1.2.3.4", "1.2.3.5", "1.2.3.6", "1.2.3.7"})

	p.realMu.Lock()
	recorded := len(p.realRoutes)
	p.realMu.Unlock()
	if recorded != 4 {
		t.Fatalf("realRoutes = %d, want 4", recorded)
	}
	if _, ok := fr.find("route replace 1.2.3.4/32 via 11.10.12.1 dev wg0"); !ok {
		t.Fatalf("missing /32 host route, calls: %v", fr.all())
	}

	p.aggregateRealRoutes(context.Background(), "11.10.12.1", "wg0")
	if _, ok := fr.find("route replace 1.2.3.4/30 via 11.10.12.1 dev wg0"); !ok {
		t.Fatalf("four adjacent /32 were not collapsed into /30, calls: %v", fr.all())
	}
}
