package fakeipnat

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/ersonw/mosdns-v4/pkg/executable_seq"
	"github.com/ersonw/mosdns-v4/pkg/query_context"
	"github.com/miekg/dns"
)

// ipv6OnlyNext answers A queries with no A records and, when enabled, AAAA
// queries with one AAAA record. It lets the test drive the fakeip plugin
// through the same next-node path used in a real sequence.
type ipv6OnlyNext struct {
	hasAAAA bool
	calls   int
}

func (n *ipv6OnlyNext) Exec(_ context.Context, qCtx *query_context.Context, _ executable_seq.ExecutableChainNode) error {
	n.calls++
	q := qCtx.Q()
	r := new(dns.Msg)
	r.SetReply(q)
	if q.Question[0].Qtype == dns.TypeAAAA && n.hasAAAA {
		r.Answer = append(r.Answer, &dns.AAAA{
			Hdr:  dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
			AAAA: net.ParseIP("2602:ffe4:c98:2910::2"),
		})
	}
	qCtx.SetResponse(r)
	return nil
}

func proxyIPv6OnlyPlugin(t *testing.T) *FakeIPNatPlugin {
	t.Helper()
	p := newRealIPPlugin(t, false)
	p.proxyActive = true
	p.useTun = true
	return p
}

func TestProxyAllocatesForIPv6OnlyDomain(t *testing.T) {
	p := proxyIPv6OnlyPlugin(t)
	n := &ipv6OnlyNext{hasAAAA: true}
	qCtx := query_context.NewContext(aQuery("ipv6-only.example."), nil)

	if err := p.Exec(context.Background(), qCtx, executable_seq.WrapExecutable(n)); err != nil {
		t.Fatalf("Exec failed: %v", err)
	}
	if n.calls != 2 {
		t.Fatalf("next calls = %d, want A and AAAA lookups", n.calls)
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

	var count int
	if err := p.db.QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM test_mapping").Scan(&count); err != nil {
		t.Fatalf("count mapping failed: %v", err)
	}
	if count != 1 {
		t.Fatalf("mapping rows = %d, want 1", count)
	}
}

func TestIPv6OnlyDomainDoesNotAllocateWithoutProxy(t *testing.T) {
	p := newRealIPPlugin(t, false)
	n := &ipv6OnlyNext{hasAAAA: true}
	qCtx := query_context.NewContext(aQuery("ipv6-only.example."), nil)

	if err := p.Exec(context.Background(), qCtx, executable_seq.WrapExecutable(n)); err != nil {
		t.Fatalf("Exec failed: %v", err)
	}
	if n.calls != 1 {
		t.Fatalf("next calls = %d, want only the original A lookup", n.calls)
	}
	var count int
	if err := p.db.QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM test_mapping").Scan(&count); err != nil {
		t.Fatalf("count mapping failed: %v", err)
	}
	if count != 0 {
		t.Fatalf("mapping rows = %d, want 0", count)
	}
}

func TestIPv6OnlyDomainWithoutAAAAIsNotAllocated(t *testing.T) {
	p := proxyIPv6OnlyPlugin(t)
	n := &ipv6OnlyNext{hasAAAA: false}
	qCtx := query_context.NewContext(aQuery("no-aaaa.example."), nil)

	if err := p.Exec(context.Background(), qCtx, executable_seq.WrapExecutable(n)); err != nil {
		t.Fatalf("Exec failed: %v", err)
	}
	if n.calls != 2 {
		t.Fatalf("next calls = %d, want A and AAAA lookups", n.calls)
	}
	if len(qCtx.R().Answer) != 0 {
		t.Fatalf("answers = %d, want no fake A record", len(qCtx.R().Answer))
	}
	var count int
	if err := p.db.QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM test_mapping").Scan(&count); err != nil {
		t.Fatalf("count mapping failed: %v", err)
	}
	if count != 0 {
		t.Fatalf("mapping rows = %d, want 0", count)
	}
}

func TestIPv6OnlyDomainReusesExistingMapping(t *testing.T) {
	p := proxyIPv6OnlyPlugin(t)
	first := &ipv6OnlyNext{hasAAAA: true}
	qCtx := query_context.NewContext(aQuery("ipv6-only.example."), nil)
	if err := p.Exec(context.Background(), qCtx, executable_seq.WrapExecutable(first)); err != nil {
		t.Fatalf("first Exec failed: %v", err)
	}
	fakeIP := qCtx.R().Answer[0].(*dns.A).A.String()

	second := &ipv6OnlyNext{hasAAAA: false}
	qCtx = query_context.NewContext(aQuery("ipv6-only.example."), nil)
	if err := p.Exec(context.Background(), qCtx, executable_seq.WrapExecutable(second)); err != nil {
		t.Fatalf("second Exec failed: %v", err)
	}
	if second.calls != 1 {
		t.Fatalf("second next calls = %d, want only the A lookup", second.calls)
	}
	if got := qCtx.R().Answer[0].(*dns.A).A.String(); got != fakeIP {
		t.Fatalf("fake ip changed: %s -> %s", fakeIP, got)
	}
}
