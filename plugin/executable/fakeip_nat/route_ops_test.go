package fakeipnat

import (
	"strings"
	"testing"
)

// countRouteCalls counts the recorded commands that mention addr and are
// writes (wantDelete false) or deletes (wantDelete true). The route command
// differs per platform, so the assertions stay platform independent.
func countRouteCalls(calls []string, prefix string, wantDelete bool) int {
	addr := prefix
	if a, _, ok := strings.Cut(prefix, "/"); ok {
		addr = a
	}
	count := 0
	for _, call := range calls {
		if !strings.Contains(call, addr) {
			continue
		}
		if strings.Contains(call, "delete") == wantDelete {
			count++
		}
	}
	return count
}

func TestNetmaskString(t *testing.T) {
	cases := map[int]string{
		32: "255.255.255.255",
		30: "255.255.255.252",
		24: "255.255.255.0",
		8:  "255.0.0.0",
	}
	for bits, want := range cases {
		if got := netmaskString(bits); got != want {
			t.Fatalf("netmaskString(%d) = %q, want %q", bits, got, want)
		}
		if back, ok := prefixMask(want); !ok || back != bits {
			t.Fatalf("prefixMask(%q) = %d (ok=%v), want %d", want, back, ok, bits)
		}
	}
	if _, ok := prefixMask("255.0.255.0"); ok {
		t.Fatal("a netmask with a hole must be rejected")
	}
}

func TestParseBSDManagedRoutes(t *testing.T) {
	out := `Routing tables

Internet:
Destination        Gateway            Flags        Netif Expire
default            192.168.88.1       UGScg          en0
1.2.3.4            11.10.12.1         UGHS           wg0
1.2.3.4/30         11.10.12.1         UGSc           wg0
198.18.0.0/15      link#12            UCS            utun4
1.2.3.9            11.10.12.1         UGHS           eth1
`
	routes := parseBSDManagedRoutes(out, "11.10.12.1", "wg0")
	want := []string{"1.2.3.4/32", "1.2.3.4/30"}
	if len(routes) != len(want) {
		t.Fatalf("routes = %v, want %v", routes, want)
	}
	for i := range want {
		if routes[i] != want[i] {
			t.Fatalf("routes = %v, want %v", routes, want)
		}
	}
}

func TestParseWindowsManagedRoutes(t *testing.T) {
	out := `
===========================================================================
IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0        0.0.0.0      192.168.1.1     192.168.1.10      25
          1.2.3.4  255.255.255.255       10.0.0.1        10.0.0.2       5
          1.2.3.4  255.255.255.252       10.0.0.1        10.0.0.2       5
        1.2.3.10  255.255.255.255       10.0.0.9        10.0.0.2       5
`
	routes := parseWindowsManagedRoutes(out, "10.0.0.1", "")
	want := []string{"1.2.3.4/32", "1.2.3.4/30"}
	if len(routes) != len(want) {
		t.Fatalf("routes = %v, want %v", routes, want)
	}
	for i := range want {
		if routes[i] != want[i] {
			t.Fatalf("routes = %v, want %v", routes, want)
		}
	}
}

func TestParseWindowsDefaultRoute(t *testing.T) {
	out := `
IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0        0.0.0.0      192.168.1.1     192.168.1.10      25
`
	hop, dev := parseWindowsDefaultRoute(out)
	if hop != "192.168.1.1" || dev != "" {
		t.Fatalf("default route = (%q,%q), want (192.168.1.1,\"\")", hop, dev)
	}
}
