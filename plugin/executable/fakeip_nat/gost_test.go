package fakeipnat

// Tests for the gost outlet: one address that may answer several protocols, of
// which the plugin keeps only the ones that actually reply.

import (
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// socksOnlyListener accepts many connections and speaks socks5 only: anything
// that does not start with the socks5 greeting byte is closed. That is what a
// gost listener pinned to one protocol looks like from the outside, and it lets
// the probe of the other flavours fail instead of hanging.
func socksOnlyListener(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				var greet [2]byte
				if _, err := io.ReadFull(c, greet[:]); err != nil {
					return
				}
				if greet[0] != 0x05 {
					return
				}
				if _, err := io.ReadFull(c, make([]byte, int(greet[1]))); err != nil {
					return
				}
				if _, err := c.Write([]byte{0x05, 0x00}); err != nil {
					return
				}
				// Consume one CONNECT so a dial can complete, then park.
				var hdr [3]byte
				if _, err := io.ReadFull(c, hdr[:]); err != nil {
					return
				}
				var atyp [1]byte
				if _, err := io.ReadFull(c, atyp[:]); err != nil {
					return
				}
				switch atyp[0] {
				case 0x01:
					_, _ = io.ReadFull(c, make([]byte, 4))
				case 0x03:
					var l [1]byte
					if _, err := io.ReadFull(c, l[:]); err != nil {
						return
					}
					_, _ = io.ReadFull(c, make([]byte, int(l[0])))
				case 0x04:
					_, _ = io.ReadFull(c, make([]byte, 16))
				}
				_, _ = io.ReadFull(c, make([]byte, 2))
				if _, err := c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
					return
				}
				_, _ = io.Copy(io.Discard, c)
			}(c)
		}
	}()
	return ln.Addr().String()
}

func TestNewEgressBuildsGostCandidates(t *testing.T) {
	d, err := newEgress("gost://admin:admin@11.10.10.13:1080", false)
	if err != nil {
		t.Fatalf("gost parse failed: %v", err)
	}
	g, ok := d.(*gostEgress)
	if !ok {
		t.Fatalf("gost link built %T, want *gostEgress", d)
	}
	if g.server != "11.10.10.13:1080" {
		t.Fatalf("gost server = %q", g.server)
	}
	if len(g.candidates) != 5 {
		t.Fatalf("gost candidates = %d, want 5", len(g.candidates))
	}
	first, ok := g.candidates[0].(*socks5Egress)
	if !ok || !first.remoteDNS {
		t.Fatalf("first candidate = %T, want socks5 with remote dns", g.candidates[0])
	}
	if first.user != "admin" || first.pass != "admin" {
		t.Fatalf("gost credentials not carried to the socks5 candidate")
	}

	noPort, err := newEgress("gost://user:pass@proxy.example", false)
	if err != nil {
		t.Fatalf("gost parse without port failed: %v", err)
	}
	if noPort.(*gostEgress).server != "proxy.example:1080" {
		t.Fatalf("gost default port = %q, want 1080", noPort.(*gostEgress).server)
	}
}

func TestGostProbeKeepsOnlyWorkingProtocols(t *testing.T) {
	addr := socksOnlyListener(t)
	g := newGostEgress(addr, "127.0.0.1", "", "", true)

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if err := g.Probe(ctx); err != nil {
		t.Fatalf("probe against a socks5 listener failed: %v", err)
	}

	got := g.protocols()
	if len(got) != 2 {
		t.Fatalf("kept %v, want only the two socks5 flavours", got)
	}
	for _, p := range got {
		if !strings.HasPrefix(p, "socks5") {
			t.Fatalf("kept %q, want socks5 only", p)
		}
	}
}

func TestGostProbeFailsWhenNothingAnswers(t *testing.T) {
	g := newGostEgress("127.0.0.1:1", "127.0.0.1", "", "", false)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := g.Probe(ctx); err == nil {
		t.Fatal("probe against a closed port must fail so the caller keeps direct egress")
	}
}

func TestGostDialFallsBackToDirect(t *testing.T) {
	// Every candidate points somewhere that refuses connections, so the dial
	// has to leave through the host network instead.
	g := newGostEgress("127.0.0.1:1", "127.0.0.1", "", "", false)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		if c, err := ln.Accept(); err == nil {
			_ = c.Close()
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := g.DialContext(ctx, "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("gost dial should fall back to direct: %v", err)
	}
	_ = c.Close()
}
