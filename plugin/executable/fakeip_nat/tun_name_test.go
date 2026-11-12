package fakeipnat

import (
	"context"
	"strings"
	"testing"
)

// TestTunDevicesParsesListing keeps the name filter honest: only <base><digits>
// names count, and the peer suffix of a veth is not part of the name.
func TestTunDevicesParsesListing(t *testing.T) {
	out := "" +
		"1: lo: <LOOPBACK,UP> mtu 65536 qdisc noqueue state UNKNOWN\n" +
		"5: mth0: <POINTOPOINT,MULTICAST,NOARP,UP> mtu 1500 qdisc fq_codel state UNKNOWN\n" +
		"6: mth3@if7: <POINTOPOINT,MULTICAST,NOARP> mtu 1500\n" +
		"7: mthx: <POINTOPOINT> mtu 1500\n" +
		"8: eth0: <BROADCAST,MULTICAST,UP> mtu 1500\n"

	names := tunDevices(out, defaultTunBase)
	if len(names) != 2 {
		t.Fatalf("parsed %d names, want 2: %v", len(names), names)
	}
	for _, want := range []string{"mth0", "mth3"} {
		if _, ok := names[want]; !ok {
			t.Fatalf("missing %s in %v", want, names)
		}
	}
}

// TestTunDeviceWithAddrFindsReserved pins the reuse rule: a leftover device is
// adopted only when it already carries the address the plugin is about to use.
func TestTunDeviceWithAddrFindsReserved(t *testing.T) {
	out := "" +
		"5: mth0    inet 10.0.0.5/24 scope global mth0\\       valid_lft forever\n" +
		"6: mth1    inet 198.18.0.1/15 scope global mth1\\       valid_lft forever\n"

	if got := tunDeviceWithAddr(out, "198.18.0.1"); got != "mth1" {
		t.Fatalf("tunDeviceWithAddr = %q, want mth1", got)
	}
	if got := tunDeviceWithAddr(out, "198.18.0.9"); got != "" {
		t.Fatalf("an unrelated address matched %q", got)
	}
}

// TestPickTunNameReusesReservedAddress proves the expensive per-name probing is
// gone: two listings decide everything, and a device with the reserved address
// wins over a free index.
func TestPickTunNameReusesReservedAddress(t *testing.T) {
	runner := &fakeRunner{
		linksOut: "5: mth0: <POINTOPOINT,UP>\n6: mth1: <POINTOPOINT,UP>\n",
		addrOut:  "6: mth1    inet 198.18.0.1/15 scope global mth1\n",
	}
	p := newNativePlugin(t, runner, func(context.Context, string) bool { return true })

	name, err := p.pickTunName(context.Background())
	if err != nil {
		t.Fatalf("pickTunName: %v", err)
	}
	if name != "mth1" {
		t.Fatalf("pickTunName = %q, want mth1", name)
	}
	if calls := len(runner.all()); calls != 2 {
		t.Fatalf("pickTunName ran %d commands, want 2:\n%s", calls, strings.Join(runner.all(), "\n"))
	}
}

// TestPickTunNameTakesTheLowestFreeIndex: without a reusable device the first
// gap is used, so restarts do not keep allocating new names.
func TestPickTunNameTakesTheLowestFreeIndex(t *testing.T) {
	runner := &fakeRunner{linksOut: "5: mth0: <POINTOPOINT,UP>\n6: mth2: <POINTOPOINT,UP>\n"}
	p := newNativePlugin(t, runner, func(context.Context, string) bool { return true })

	name, err := p.pickTunName(context.Background())
	if err != nil {
		t.Fatalf("pickTunName: %v", err)
	}
	if name != "mth1" {
		t.Fatalf("pickTunName = %q, want mth1", name)
	}
}
