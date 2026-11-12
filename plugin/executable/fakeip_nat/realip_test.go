package fakeipnat

import (
	"context"
	"net"
	"net/netip"
	"path/filepath"
	"strings"
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
	// Wait for the startup queue before swapping the runner in: a queued sweep
	// that read the kernel through the fake runner would delete the ledger rows
	// the test is about to install.
	p.startupWG.Wait()
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

func TestRealIPRoutesAreAggregatedFromTheTable(t *testing.T) {
	p := newRealIPPlugin(t, true)
	fr := p.runner.(*fakeRunner)

	p.syncRealRoutes(context.Background(), []string{"1.2.3.4", "1.2.3.5", "1.2.3.6", "1.2.3.7"})

	p.realMu.Lock()
	recorded := len(p.realRoutes)
	p.realMu.Unlock()
	if recorded != 4 {
		t.Fatalf("realRoutes = %d, want 4", recorded)
	}
	if countRouteCalls(fr.all(), "1.2.3.4", false) == 0 {
		t.Fatalf("missing host route for 1.2.3.4, calls: %v", fr.all())
	}
	if !strings.Contains(strings.Join(fr.all(), "\n"), "11.10.12.1") {
		t.Fatalf("host route does not target the gateway, calls: %v", fr.all())
	}

	// The periodic scan reads the kernel table, so feed what a previous pass
	// would have found there.
	routes := []string{"1.2.3.4/32", "1.2.3.5/32", "1.2.3.6/32", "1.2.3.7/32"}
	p.collapseManagedRoutes(context.Background(), routes, "11.10.12.1", "wg0")
	joined := strings.Join(fr.all(), "\n")
	if !strings.Contains(joined, "1.2.3.4") ||
		(!strings.Contains(joined, "/30") && !strings.Contains(joined, "255.255.255.252")) {
		t.Fatalf("four adjacent /32 were not collapsed into /30, calls: %v", fr.all())
	}
}
