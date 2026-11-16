package routepolicy

import (
	"strings"
	"testing"
)

func TestClaimRejectsASecondOwner(t *testing.T) {
	r := NewRegistry()
	if err := r.Claim(Claim{Owner: "fakeip_nat", Mark: 0x1, Table: "100", Priority: 1200}); err != nil {
		t.Fatalf("first claim failed: %v", err)
	}
	err := r.Claim(Claim{Owner: "asn_tun", Mark: 0x1, Table: "123", Priority: 5000})
	if err == nil {
		t.Fatal("a second owner on the same mark must be rejected")
	}
	for _, want := range []string{"fakeip_nat", "asn_tun", "mark=0x1"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name %q", err, want)
		}
	}
}

func TestSameOwnerMayReclaim(t *testing.T) {
	r := NewRegistry()
	first := Claim{Owner: "fakeip_nat", Mark: 0x1, Table: "100", Priority: 1200}
	if err := r.Claim(first); err != nil {
		t.Fatalf("claim failed: %v", err)
	}
	// A restart installs the same object again; that is not a conflict.
	if err := r.Claim(first); err != nil {
		t.Fatalf("re-claim by the same owner should be accepted: %v", err)
	}
	if n := len(r.Claims()); n != 1 {
		t.Fatalf("registry holds %d claims, want 1", n)
	}
}

func TestSourceRulesAreKeyedByTableAndPriority(t *testing.T) {
	r := NewRegistry()
	if err := r.Claim(Claim{Owner: "alias", Table: "100", Priority: 1200}); err != nil {
		t.Fatalf("claim failed: %v", err)
	}
	// A different table is a different object.
	if err := r.Claim(Claim{Owner: "egress_route", Table: "200", Priority: 1200}); err != nil {
		t.Fatalf("a distinct table must not collide: %v", err)
	}
	// The same table at the same priority is the same rule.
	if err := r.Claim(Claim{Owner: "asn_tun", Table: "100", Priority: 1200}); err == nil {
		t.Fatal("the same source rule claimed twice must be rejected")
	}
}

func TestReleaseFreesTheOwner(t *testing.T) {
	r := NewRegistry()
	claim := Claim{Owner: "fakeip_nat", Mark: 0x1, Table: "100"}
	if err := r.Claim(claim); err != nil {
		t.Fatalf("claim failed: %v", err)
	}
	r.Release("fakeip_nat")
	if n := len(r.Claims()); n != 0 {
		t.Fatalf("release left %d claims", n)
	}
	if err := r.Claim(Claim{Owner: "asn_tun", Mark: 0x1, Table: "123"}); err != nil {
		t.Fatalf("a released mark should be claimable: %v", err)
	}
}

func TestClaimNeedsAnOwnerAndAnObject(t *testing.T) {
	r := NewRegistry()
	if err := r.Claim(Claim{Table: "100"}); err == nil {
		t.Fatal("a claim without an owner must fail")
	}
	if err := r.Claim(Claim{Owner: "alias"}); err == nil {
		t.Fatal("a claim that names neither mark nor table must fail")
	}
}
