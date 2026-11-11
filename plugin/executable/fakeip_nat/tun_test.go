package fakeipnat

import (
	"context"
	"net/netip"
	"strings"
	"testing"
)

// Every platform describes its setup as a command plan; the plans are pure
// data, so all of them can be checked on any host.

func TestLinuxTunCommandPlan(t *testing.T) {
	create := linuxCreateTunCommands("mth3")
	if len(create) != 1 || strings.Join(create[0].args, " ") != "ip tuntap add dev mth3 mode tun" {
		t.Fatalf("create plan = %v", create)
	}

	plan := linuxConfigureTunCommands("mth3", "198.18.0.1", "198.18.0.0/16")
	want := []string{
		"ip link set dev mth3 up",
		"ip addr replace 198.18.0.1/16 dev mth3",
		"sysctl -w net.ipv6.conf.mth3.disable_ipv6=1",
	}
	if len(plan) != len(want) {
		t.Fatalf("plan has %d steps, want %d: %v", len(plan), len(want), plan)
	}
	for i, w := range want {
		if got := strings.Join(plan[i].args, " "); got != w {
			t.Fatalf("step %d = %q, want %q", i, got, w)
		}
	}
	// IPv6 goes off on a best effort basis: a restricted netns may refuse it and
	// that must not abort the setup.
	if !plan[len(plan)-1].optional {
		t.Fatal("the ipv6 sysctl step must be optional")
	}
}

func TestBSDTunCommandPlan(t *testing.T) {
	plan := bsdConfigureTunCommands("utun4", "198.18.0.1", "198.18.0.0/16")
	want := []string{
		"ifconfig utun4 inet 198.18.0.1 198.18.0.1 netmask 255.255.255.255 up",
		"route delete -net 198.18.0.0/16",
		"route add -net 198.18.0.0/16 -interface utun4",
	}
	if len(plan) != len(want) {
		t.Fatalf("plan has %d steps, want %d: %v", len(plan), len(want), plan)
	}
	for i, w := range want {
		if got := strings.Join(plan[i].args, " "); got != w {
			t.Fatalf("step %d = %q, want %q", i, got, w)
		}
	}
	// The delete only cleans up a rule from a previous run.
	if !plan[1].optional || plan[2].optional {
		t.Fatalf("route delete must be optional and route add must be fatal: %v", plan)
	}
}

func TestWindowsTunCommandPlan(t *testing.T) {
	plan := windowsConfigureTunCommands("mth2", "198.18.0.1", "198.18.0.0/16")
	want := []string{
		"netsh interface ipv4 set address name=mth2 source=static address=198.18.0.1 mask=255.255.255.255",
		"netsh interface ipv4 delete route prefix=198.18.0.0/16 interface=mth2",
		"netsh interface ipv4 add route prefix=198.18.0.0/16 interface=mth2 metric=1",
	}
	if len(plan) != len(want) {
		t.Fatalf("plan has %d steps, want %d: %v", len(plan), len(want), plan)
	}
	for i, w := range want {
		if got := strings.Join(plan[i].args, " "); got != w {
			t.Fatalf("step %d = %q, want %q", i, got, w)
		}
	}
	if !plan[1].optional {
		t.Fatalf("route delete must be optional: %v", plan)
	}
}

func TestApplyTunCommandsSkipsOptionalFailure(t *testing.T) {
	runner := &fakeRunner{failContains: "route delete"}
	p := newNativePlugin(t, runner, nil)

	err := p.applyTunCommands(context.Background(), bsdConfigureTunCommands("utun0", "198.18.0.1", "198.18.0.0/16"))
	if err != nil {
		t.Fatalf("a failing optional step must not abort setup: %v", err)
	}

	runner = &fakeRunner{failContains: "route add"}
	p = newNativePlugin(t, runner, nil)
	if err := p.applyTunCommands(context.Background(), bsdConfigureTunCommands("utun0", "198.18.0.1", "198.18.0.0/16")); err == nil {
		t.Fatal("a failing mandatory step must abort setup")
	}
}

// The device owns the first host of the range, so the allocator must start one
// address later and never hand that address to a domain.
func TestTunAddressIsReservedForDevice(t *testing.T) {
	p := newTestPlugin(t, "198.18.0.0/16")

	if got := p.reservedFakeIP(); got != "198.18.0.1" {
		t.Fatalf("reservedFakeIP = %q, want 198.18.0.1", got)
	}
	if got, err := p.allocateFakeIP(1); err != nil || got != "198.18.0.2" {
		t.Fatalf("allocateFakeIP(1) = %q, %v, want 198.18.0.2", got, err)
	}
	for id := uint64(1); id <= 10; id++ {
		got, err := p.allocateFakeIP(id)
		if err != nil {
			t.Fatalf("allocateFakeIP(%d) failed: %v", id, err)
		}
		if got == "198.18.0.1" {
			t.Fatalf("row id %d got the reserved device address", id)
		}
		if !p.prefix.Contains(netip.MustParseAddr(got)) {
			t.Fatalf("row id %d escaped %s: %s", id, p.cidr, got)
		}
	}
	// Wrapping must stay inside the allocatable part of the range.
	for _, id := range []uint64{65534, 65535, 1 << 40} {
		got, err := p.allocateFakeIP(id)
		if err != nil {
			t.Fatalf("allocateFakeIP(%d) failed: %v", id, err)
		}
		if got == "198.18.0.1" || got == "198.18.255.255" || got == "198.18.0.0" {
			t.Fatalf("allocateFakeIP(%d) = %s, want an allocatable address", id, got)
		}
	}
}

func TestSmallRangeKeepsOneAllocatableHost(t *testing.T) {
	p := newTestPlugin(t, "198.18.0.0/30")
	for id := uint64(1); id <= 3; id++ {
		got, err := p.allocateFakeIP(id)
		if err != nil {
			t.Fatalf("allocateFakeIP(%d) failed: %v", id, err)
		}
		if got != "198.18.0.2" {
			t.Fatalf("allocateFakeIP(%d) = %s, want 198.18.0.2", id, got)
		}
	}
}
