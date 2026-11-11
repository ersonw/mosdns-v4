package fakeipnat

import (
	"strings"
	"testing"
)

func TestTunSNATPlan(t *testing.T) {
	plan := tunSNATPlan("test_tun_snat", "eth0", "198.18.0.0/15")
	if len(plan) != 4 {
		t.Fatalf("plan has %d commands, want 4", len(plan))
	}
	if got := strings.Join(plan[0], " "); got != "delete table ip test_tun_snat" {
		t.Fatalf("first command = %q, want the stale table cleanup", got)
	}
	want := "add rule ip test_tun_snat postrouting oifname eth0 ip saddr 198.18.0.0/15 masquerade"
	if got := strings.Join(plan[3], " "); got != want {
		t.Fatalf("rule = %q, want %q", got, want)
	}

	if plan := tunSNATPlan("test_tun_snat", "", "198.18.0.0/15"); plan != nil {
		t.Fatal("a plan without an egress device must not be built")
	}
	if plan := tunSNATPlan("test_tun_snat", "eth0", ""); plan != nil {
		t.Fatal("a plan without a range must not be built")
	}
}

func TestTunSNATTableName(t *testing.T) {
	p := newTestPlugin(t, "198.18.0.0/24")
	if got := p.tunSNATTableName(); got != "test_tun_snat" {
		t.Fatalf("tunSNATTableName() = %q, want test_tun_snat", got)
	}
}
