//go:build darwin

package fakeipnat

import (
	"context"
	"strings"
	"testing"
)

// macOS assigns utun numbers itself: unit 0 means "give me the first free one".
// A configured tun_dev therefore cannot be created on demand - if it exists it
// belongs to another process, and if it does not exist the kernel still refuses
// the explicit unit with EBUSY.
func TestDarwinTunUnitFromConfigRejectsExistingDevice(t *testing.T) {
	p := newNativePlugin(t, &fakeRunner{}, nil) // every ifconfig probe succeeds
	p.tunDev = "utun7"

	if _, err := p.darwinTunUnit(context.Background()); err == nil {
		t.Fatal("an existing utun7 must be rejected instead of failing later with EBUSY")
	}
}

func TestDarwinTunUnitFromConfigFallsBackToKernel(t *testing.T) {
	runner := &fakeRunner{ifaces: map[string]bool{"utun0": true}}
	p := newNativePlugin(t, runner, nil)
	p.tunDev = "utun7" // not present on this host

	unit, err := p.darwinTunUnit(context.Background())
	if err != nil {
		t.Fatalf("darwinTunUnit: %v", err)
	}
	if unit != 0 {
		t.Fatalf("unit = %d, want 0 so the kernel picks the free unit", unit)
	}
}

func TestDarwinTunUnitRejectsForeignName(t *testing.T) {
	p := newNativePlugin(t, &fakeRunner{}, nil)
	p.tunDev = "mth0"

	if _, err := p.darwinTunUnit(context.Background()); err == nil {
		t.Fatal("darwin requires utun<N>, so mth0 must be rejected")
	}
}

func TestDarwinTunUnitLetsKernelChoose(t *testing.T) {
	runner := &fakeRunner{ifaces: map[string]bool{"utun0": true, "utun1": true}}
	p := newNativePlugin(t, runner, nil)

	unit, err := p.darwinTunUnit(context.Background())
	if err != nil {
		t.Fatalf("darwinTunUnit: %v", err)
	}
	if unit != 0 {
		t.Fatalf("unit = %d, want 0: the kernel assigns the first free utun", unit)
	}
	if calls := runner.all(); len(calls) != 0 {
		t.Fatalf("auto mode must not probe ifconfig, got %v", calls)
	}
}

func TestDarwinConfigureCommands(t *testing.T) {
	p := newNativePlugin(t, &fakeRunner{}, nil)
	plan := p.tunConfigureCommands("utun3")
	// Point-to-point devices need a peer address, otherwise ifconfig answers
	// "ioctl (SIOCAIFADDR): Destination address required" (verified on macOS).
	want := "ifconfig utun3 inet 198.18.0.1 198.18.0.1 netmask 255.255.255.255 up"
	if got := strings.Join(plan[0].args, " "); got != want {
		t.Fatalf("first step = %q, want %q", got, want)
	}
}
