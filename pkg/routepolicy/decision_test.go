package routepolicy

import (
	"strings"
	"testing"

	"github.com/ersonw/mosdns-v4/pkg/pipeline"
	"github.com/ersonw/mosdns-v4/pkg/query_context"
	"github.com/miekg/dns"
)

func newCtx(t *testing.T) *query_context.Context {
	t.Helper()
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	return query_context.NewContext(q, nil)
}

func TestDecisionKeepsItsOwner(t *testing.T) {
	ctx := newCtx(t)
	fakeip := pipeline.Owner("fakeip_nat")
	asn := pipeline.Owner("asn_tun")

	SetDecision(ctx, fakeip, Decision{Mark: 0x1, Table: "100", Priority: 1200, NextHop: "192.168.10.254", Dev: "eth0"})
	SetDecision(ctx, asn, Decision{Mark: 0x2, Table: "123", Priority: 5000, Dev: "asn0"})

	got, ok := DecisionFor(ctx, fakeip)
	if !ok || got.Table != "100" || got.Mark != 0x1 {
		t.Fatalf("fakeip decision = %+v, %v", got, ok)
	}
	got, ok = DecisionFor(ctx, asn)
	if !ok || got.Table != "123" || got.Mark != 0x2 {
		t.Fatalf("asn decision = %+v, %v", got, ok)
	}
}

func TestDecisionsListsBothPlugins(t *testing.T) {
	ctx := newCtx(t)
	SetDecision(ctx, pipeline.Owner("fakeip_nat"), Decision{Mark: 0x1, Table: "100"})
	SetDecision(ctx, pipeline.Owner("alias"), Decision{Table: "100", Priority: 1200})

	all := Decisions(ctx)
	if len(all) != 2 {
		t.Fatalf("expected two owners, got %d: %+v", len(all), all)
	}
	if all["alias"].Mark != 0 {
		t.Fatalf("alias decision should carry no mark: %+v", all["alias"])
	}
}

func TestDecisionStringSeparatesTwoDecisions(t *testing.T) {
	a := Decision{Mark: 0x1, NFTable: "fakeip", Table: "100", Priority: 1200, NextHop: "192.168.10.254", Dev: "eth0"}
	b := Decision{Table: "100", Priority: 1200, Dev: "tun0"}

	lineA, lineB := a.String(), b.String()
	if lineA == lineB {
		t.Fatalf("two different decisions print the same line: %s", lineA)
	}
	for _, want := range []string{"mark=0x1", "table=100", "prio=1200", "via=192.168.10.254", "dev=eth0"} {
		if !strings.Contains(lineA, want) {
			t.Errorf("decision line %q is missing %q", lineA, want)
		}
	}
	if !strings.Contains(lineB, "mark=none") || !strings.Contains(lineB, "via=device only") {
		t.Errorf("a sourceless decision should say so: %q", lineB)
	}
}
