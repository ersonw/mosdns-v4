package fakeipnat

import (
	"reflect"
	"testing"

	"github.com/ersonw/mosdns-v4/pkg/routepolicy"
)

// The exit owns the routing half, so a borrower that names it takes those
// values and says out loud which local copies were dropped.
func TestAdoptExitFieldsTunTakesWholeDecision(t *testing.T) {
	cfg := &Args{RouteMark: 110, RouteTable: "111", RouteRulePriority: 1001, NextHop: "11.10.12.1", NextHopDev: "wg0"}
	d := routepolicy.Decision{Mark: 126, NFTable: "asn_tun", Table: "126", Priority: 1001, NextHop: "11.10.12.1", Dev: "wg0"}

	got, ignored := adoptExitFields(cfg, d, true, false)

	want := borrowedExitFields{Mark: 126, Table: "126", Priority: 1001, NextHop: "11.10.12.1", Dev: "wg0"}
	if got != want {
		t.Fatalf("adopted = %+v, want %+v", got, want)
	}
	wantIgnored := []string{"route_mark", "route_table", "route_rule_priority", "next_hop", "next_hop_dev"}
	if !reflect.DeepEqual(ignored, wantIgnored) {
		t.Fatalf("ignored = %v, want %v", ignored, wantIgnored)
	}
}

// Default values are not declarations: a table of "main" or the default rule
// priority must not be reported as a dropped field.
func TestAdoptExitFieldsIgnoresDefaults(t *testing.T) {
	cfg := &Args{RouteTable: "main", RouteRulePriority: defaultRouteRulePriority}
	d := routepolicy.Decision{Mark: 126, Table: "126", Priority: 1001, Dev: "wg0"}

	_, ignored := adoptExitFields(cfg, d, true, false)
	if len(ignored) != 0 {
		t.Fatalf("ignored = %v, want none for default values", ignored)
	}
}

// With a routed exit that takes destinations the whole routing half is the
// exit's, including the mark and the table the NAT path used to install.
func TestAdoptExitFieldsNatWithRegistrarLeavesKernelToExit(t *testing.T) {
	cfg := &Args{RouteMark: 110, RouteTable: "111", NextHop: "10.0.0.1"}
	d := routepolicy.Decision{Mark: 126, NFTable: "asn_tun", Table: "126", Priority: 1001, NextHop: "11.10.12.1", Dev: "wg0"}

	got, ignored := adoptExitFields(cfg, d, false, true)

	want := borrowedExitFields{Mark: 126, Table: "126", Priority: 1001, NextHop: "11.10.12.1", Dev: "wg0"}
	if got != want {
		t.Fatalf("adopted = %+v, want %+v", got, want)
	}
	if !reflect.DeepEqual(ignored, []string{"route_mark", "route_table", "next_hop"}) {
		t.Fatalf("ignored = %v, want the three declared fields", ignored)
	}
}

// Without a destination set the exit cannot route what this plugin maps, so the
// NAT path keeps its own mark and table and only borrows the route.
func TestAdoptExitFieldsNatWithoutRegistrarKeepsMark(t *testing.T) {
	cfg := &Args{RouteMark: 110, RouteTable: "111"}
	d := routepolicy.Decision{Mark: 126, Table: "126", Priority: 1001, NextHop: "11.10.12.1", Dev: "wg0"}

	got, ignored := adoptExitFields(cfg, d, false, false)

	want := borrowedExitFields{NextHop: "11.10.12.1", Dev: "wg0"}
	if got != want {
		t.Fatalf("adopted = %+v, want %+v", got, want)
	}
	if !reflect.DeepEqual(ignored, []string(nil)) {
		t.Fatalf("ignored = %v, want none: the mark stays local here", ignored)
	}
}
