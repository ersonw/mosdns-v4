package sni_route

import (
	"context"
	"net/netip"
	"testing"

	"github.com/ersonw/mosdns-v4/pkg/query_context"
	"github.com/miekg/dns"
)

type captureMatcher struct {
	matched   bool
	gotClient netip.Addr
	gotName   string
	gotType   uint16
	gotClass  uint16
}

func (m *captureMatcher) Match(_ context.Context, qCtx *query_context.Context) (bool, error) {
	q := qCtx.Q()
	if len(q.Question) > 0 {
		m.gotName = q.Question[0].Name
		m.gotType = q.Question[0].Qtype
		m.gotClass = q.Question[0].Qclass
	}
	m.gotClient = qCtx.ReqMeta().ClientAddr
	return m.matched, nil
}

func TestMatchSNIBuildsQueryForMatchers(t *testing.T) {
	client := netip.MustParseAddr("192.168.10.22")
	m := &captureMatcher{matched: true}
	p := &Plugin{}
	p.matchers = append(p.matchers, m)

	if !p.matchSNI(context.Background(), "www.tiktok.com", client) {
		t.Fatal("expected matcher hit")
	}
	if m.gotName != "www.tiktok.com." {
		t.Fatalf("question name = %q", m.gotName)
	}
	if m.gotType != dns.TypeA || m.gotClass != dns.ClassINET {
		t.Fatalf("question type/class = %d/%d", m.gotType, m.gotClass)
	}
	if m.gotClient != client {
		t.Fatalf("client = %v", m.gotClient)
	}

	m.matched = false
	if p.matchSNI(context.Background(), "www.tiktok.com", client) {
		t.Fatal("expected unmatched")
	}
	if p.matchSNI(context.Background(), "", client) {
		t.Fatal("empty SNI must not match")
	}
}

func TestMatchSNIFallsBackToDomainFileRules(t *testing.T) {
	matcher, err := newDomainMatcher([]string{"tiktokv.com"})
	if err != nil {
		t.Fatal(err)
	}
	p := &Plugin{}
	p.rules.Replace(matcher)
	if !p.matchSNI(context.Background(), "api16-core.tiktokv.com", netip.Addr{}) {
		t.Fatal("domain_file suffix rule should match")
	}
}
