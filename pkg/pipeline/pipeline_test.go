package pipeline

import (
	"testing"

	"github.com/ersonw/mosdns-v4/pkg/query_context"
	"github.com/miekg/dns"
)

func newCtx(t *testing.T) *query_context.Context {
	t.Helper()
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	return query_context.NewContext(q, nil)
}

type route struct {
	Table string
	Mark  uint32
}

func TestOwnersDoNotShareAValue(t *testing.T) {
	ctx := newCtx(t)
	key := NewKey[route]("test.route")

	fakeip := Owner("fakeip_nat")
	asn := Owner("asn_tun")
	Set(ctx, key, fakeip, route{Table: "100", Mark: 0x1})
	Set(ctx, key, asn, route{Table: "123", Mark: 0x2})

	got, ok := Get(ctx, key, fakeip)
	if !ok || got.Table != "100" || got.Mark != 0x1 {
		t.Fatalf("fakeip read %+v, %v", got, ok)
	}
	got, ok = Get(ctx, key, asn)
	if !ok || got.Table != "123" || got.Mark != 0x2 {
		t.Fatalf("asn read %+v, %v", got, ok)
	}
}

func TestUnknownOwnerReadsNothing(t *testing.T) {
	ctx := newCtx(t)
	key := NewKey[route]("test.route")
	Set(ctx, key, Owner("fakeip_nat"), route{Table: "100"})

	if _, ok := Get(ctx, key, Owner("alias")); ok {
		t.Fatal("a plugin that never stored a decision must not read one")
	}
	if Has(ctx, key, Owner("alias")) {
		t.Fatal("Has must report the same absence as Get")
	}
}

func TestResetReplacesTheEarlierValue(t *testing.T) {
	ctx := newCtx(t)
	key := NewKey[route]("test.route")
	owner := Owner("fakeip_nat")

	Set(ctx, key, owner, route{Table: "100"})
	Set(ctx, key, owner, route{Table: "200", Mark: 0x9})

	got, ok := Get(ctx, key, owner)
	if !ok || got.Table != "200" {
		t.Fatalf("re-set should win, got %+v %v", got, ok)
	}
	if n := len(Snapshot(ctx, key)); n != 1 {
		t.Fatalf("same owner holds %d entries, want 1", n)
	}
}

func TestSnapshotNamesEveryOwner(t *testing.T) {
	ctx := newCtx(t)
	key := NewKey[route]("test.route")
	Set(ctx, key, Owner("fakeip_nat"), route{Table: "100"})
	Set(ctx, key, Owner("asn_tun"), route{Table: "123"})

	all := Snapshot(ctx, key)
	if len(all) != 2 {
		t.Fatalf("snapshot has %d owners, want 2", len(all))
	}
	if all["fakeip_nat"].Table != "100" || all["asn_tun"].Table != "123" {
		t.Fatalf("snapshot mixed owners up: %+v", all)
	}
}

func TestTwoKeysOfTheSameTypeDoNotCollide(t *testing.T) {
	ctx := newCtx(t)
	first := NewKey[route]("first")
	second := NewKey[route]("second")
	owner := Owner("fakeip_nat")

	Set(ctx, first, owner, route{Table: "100"})
	Set(ctx, second, owner, route{Table: "200"})

	if got, _ := Get(ctx, first, owner); got.Table != "100" {
		t.Fatalf("first slot = %+v", got)
	}
	if got, _ := Get(ctx, second, owner); got.Table != "200" {
		t.Fatalf("second slot = %+v", got)
	}
}

func TestDeleteWithdrawsTheValue(t *testing.T) {
	ctx := newCtx(t)
	key := NewKey[route]("test.route")
	owner := Owner("fakeip_nat")
	Set(ctx, key, owner, route{Table: "100"})

	Delete(ctx, key, owner)
	if _, ok := Get(ctx, key, owner); ok {
		t.Fatal("value survived the delete")
	}
}

func TestCopySnapshotsTheValues(t *testing.T) {
	ctx := newCtx(t)
	key := NewKey[route]("test.route")
	owner := Owner("fakeip_nat")
	Set(ctx, key, owner, route{Table: "100"})

	branch := ctx.Copy()
	if got, ok := Get(branch, key, owner); !ok || got.Table != "100" {
		t.Fatalf("branch cannot see the decision made before the fork: %+v %v", got, ok)
	}

	// A sibling branch must not be able to change what its parent decided.
	Set(branch, key, Owner("alias"), route{Table: "999"})
	if _, ok := Get(ctx, key, Owner("alias")); ok {
		t.Fatal("a branch write leaked into the parent context")
	}
}

func TestValueOfAnotherTypeIsNotReturned(t *testing.T) {
	ctx := newCtx(t)
	// Two different slots of different types share one opaque store; a lookup
	// must fail rather than reinterpret the stored value.
	text := NewKey[string]("text")
	routeKey := NewKey[route]("route")
	owner := Owner("fakeip_nat")

	Set(ctx, text, owner, "100")
	if _, ok := Get(ctx, routeKey, owner); ok {
		t.Fatal("a string was returned as a route")
	}
}
