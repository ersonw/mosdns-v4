package egress

import (
	"context"
	"net"
	"strings"
	"testing"
)

// A strict exit must refuse the host network once every proxy flavour failed:
// falling back there would put the flow the exit exists to carry on the local
// address, and do it without saying so.
func TestGostEgressStrictModeRefusesDirectFallback(t *testing.T) {
	e := &gostEgress{server: "proxy.example:1080", noFallback: true}

	conn, err := e.DialContext(context.Background(), "tcp", "example.com:443")
	if err == nil {
		if conn != nil {
			_ = conn.Close()
		}
		t.Fatalf("strict gost exit dialed without a candidate, want an error")
	}
	if !strings.Contains(err.Error(), "direct fallback is disabled") {
		t.Fatalf("strict dial error = %q, want it to name the disabled fallback", err)
	}
}

// Without strict mode the same empty candidate list keeps the old behaviour:
// the flow leaves from this host.
func TestGostEgressWithoutStrictModeFallsBack(t *testing.T) {
	e := &gostEgress{server: "proxy.example:1080"}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	conn, err := e.DialContext(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial with fallback: %v", err)
	}
	_ = conn.Close()
}

// Only a multi-protocol outlet has a fallback to disable; a single-protocol
// link already fails on its own, and a false result there is not a failure.
func TestSetNoDirectFallbackOnlyAppliesToGost(t *testing.T) {
	g := &gostEgress{server: "proxy.example:1080"}
	if !SetNoDirectFallback(g) {
		t.Fatalf("SetNoDirectFallback(gost) = false, want true")
	}
	if !g.noFallback {
		t.Fatalf("SetNoDirectFallback did not set the flag on the gost exit")
	}

	s := &socks5Egress{server: "proxy.example:1080"}
	if SetNoDirectFallback(s) {
		t.Fatalf("SetNoDirectFallback(socks5) = true, want false")
	}
}
