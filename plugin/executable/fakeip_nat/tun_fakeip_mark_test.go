package fakeipnat

import (
	"context"
	"runtime"
	"strings"
	"testing"
)

// TestValidateRouteMarkNeverRejectsACombination: the combination of route_mark
// with use_tun and fakeip is legal. Rejecting it took the whole resolver down
// before the plugin could even start, which is what this test exists to stop
// from coming back.
func TestValidateRouteMarkNeverRejectsACombination(t *testing.T) {
	for _, useTun := range []bool{false, true} {
		for _, realIP := range []bool{false, true} {
			cfg := &Args{RouteMark: 0x7b, RouteTable: "123", UseTun: useTun, RealIP: realIP}
			err := validateRouteMark(cfg, 1000)
			if err != nil && strings.Contains(err.Error(), "needs realip") {
				t.Fatalf("use_tun=%v realip=%v still rejected the combination: %v", useTun, realIP, err)
			}
			// A named table only exists on linux, so the platform gate is the
			// one error that is still legitimate.
			if runtime.GOOS == "linux" && err != nil {
				t.Fatalf("use_tun=%v realip=%v rejected on linux: %v", useTun, realIP, err)
			}
		}
	}
}

// TestMarkRoutingEnabledDecidesAtRunTime pins the three meanings of the mark.
func TestMarkRoutingEnabledDecidesAtRunTime(t *testing.T) {
	cases := []struct {
		name        string
		useTun      bool
		realIP      bool
		proxyActive bool
		mark        uint32
		want        bool
	}{
		{"nat path", false, false, false, 0x7b, true},
		{"nat path with a parsed proxy", false, false, true, 0x7b, true},
		{"tun fakeip direct", true, false, false, 0x7b, true},
		{"tun fakeip through the proxy", true, false, true, 0x7b, false},
		{"tun realip direct", true, true, false, 0x7b, true},
		{"tun realip through the proxy", true, true, true, 0x7b, true},
		{"no mark configured", true, false, false, 0, false},
	}
	for _, c := range cases {
		p := &FakeIPNatPlugin{useTun: c.useTun, realIP: c.realIP, proxyActive: c.proxyActive, routeMark: c.mark}
		if got := p.markRoutingEnabled(); got != c.want {
			t.Fatalf("%s: markRoutingEnabled = %v, want %v", c.name, got, c.want)
		}
	}
}

// TestSetupMarkRoutingTunFakeipPointsAtTheNextHop: with fake answers the stack
// dials the real destinations itself, so the marked traffic has to leave towards
// next_hop/next_hop_dev. Pointing it at the device would send the stack's own
// dial back into the device it came from.
func TestSetupMarkRoutingTunFakeipPointsAtTheNextHop(t *testing.T) {
	runner := &fakeRunner{}
	p := newNativePlugin(t, runner, func(context.Context, string) bool { return true })
	p.useTun = true
	p.proxyActive = false
	p.routeMark = 0x7b
	p.routeTable = "123"
	p.nextHop = "11.10.12.1"
	p.nextHopDev = "wg0"
	p.tunDev = "mth0"

	if err := p.setupMarkRouting(context.Background()); err != nil {
		t.Fatalf("setupMarkRouting: %v", err)
	}
	if !p.markActiveNow() {
		t.Fatalf("mark path not marked active")
	}

	calls := strings.Join(runner.all(), "\n")
	if want := "ip route replace default via 11.10.12.1 dev wg0 table 123"; !strings.Contains(calls, want) {
		t.Fatalf("missing %q in:\n%s", want, calls)
	}
	if strings.Contains(calls, "dev mth0 table 123") {
		t.Fatalf("marked traffic was pointed back into the device:\n%s", calls)
	}
}

// TestSetupMarkRoutingTunRealipPointsAtTheDevice is the other half of the split:
// realip answers carry real addresses, and the device is what routes them into
// the proxy.
func TestSetupMarkRoutingTunRealipPointsAtTheDevice(t *testing.T) {
	runner := &fakeRunner{}
	p := newNativePlugin(t, runner, func(context.Context, string) bool { return true })
	p.useTun = true
	p.realIP = true
	p.routeMark = 0x7b
	p.routeTable = "123"
	p.tunDev = "mth0"

	if err := p.setupMarkRouting(context.Background()); err != nil {
		t.Fatalf("setupMarkRouting: %v", err)
	}
	calls := strings.Join(runner.all(), "\n")
	if want := "ip route replace default dev mth0 table 123"; !strings.Contains(calls, want) {
		t.Fatalf("missing %q in:\n%s", want, calls)
	}
}

// TestMarkRealIPsBatchesOneCommand keeps the answered real ips in a single nft
// call: a resolution that returns several A records must not spawn one process
// per address.
func TestMarkRealIPsBatchesOneCommand(t *testing.T) {
	runner := &fakeRunner{}
	p := newNativePlugin(t, runner, func(context.Context, string) bool { return true })
	p.routeMark = 0x7b
	p.routeTable = "123"

	if err := p.markRealIPs(context.Background(), []string{"1.2.3.4", "5.6.7.8"}); err != nil {
		t.Fatalf("markRealIPs: %v", err)
	}
	want := "nft add element ip fakeip_test real_ipv4 { 1.2.3.4, 5.6.7.8 }"
	var found int
	for _, call := range runner.all() {
		if call == want {
			found++
		}
	}
	if found != 1 {
		t.Fatalf("%q issued %d times, want 1:\n%s", want, found, strings.Join(runner.all(), "\n"))
	}
}
