package fakeipnat

// Tests for the gost outlet: one address that may answer several protocols.
// The outlet has to keep only the flavours that reply, order them by handshake
// time for TCP, and keep for UDP only the ones that granted an association.

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// socksUDPListener accepts many connections and speaks socks5 only: anything
// that does not start with the socks5 greeting is closed, which is what a gost
// listener pinned to socks5 looks like. UDP ASSOCIATE is answered with the
// address of a real relay socket, so the UDP capability check can succeed.
func socksUDPListener(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	relay, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("udp relay: %v", err)
	}
	t.Cleanup(func() { _ = relay.Close() })

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

				var hdr [3]byte // ver, cmd, rsv
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

				if hdr[1] == 0x03 { // UDP ASSOCIATE
					addr := relay.LocalAddr().(*net.UDPAddr)
					reply := []byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, byte(addr.Port >> 8), byte(addr.Port)}
					if _, err := c.Write(reply); err != nil {
						return
					}
					_, _ = io.Copy(io.Discard, c)
					return
				}
				_, _ = c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
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
	if len(g.all) != 5 {
		t.Fatalf("gost candidates = %d, want 5", len(g.all))
	}
	first, ok := g.all[0].(*socks5Egress)
	if !ok || !first.remoteDNS {
		t.Fatalf("first candidate = %T, want socks5 with remote dns", g.all[0])
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

// A listener that only speaks socks5 answers the socks5 flavours and nothing
// else, and it grants UDP, so both lists have to hold the two socks5 entries.
func TestGostProbeSplitsTCPAndUDP(t *testing.T) {
	addr := socksUDPListener(t)
	g := newGostEgress(addr, "127.0.0.1", "", "", true)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := g.Probe(ctx); err != nil {
		t.Fatalf("probe against a socks5 listener failed: %v", err)
	}

	if len(g.tcp) != 2 {
		t.Fatalf("kept %v for tcp, want the two socks5 flavours", g.tcpProtocols())
	}
	for _, p := range g.tcpProtocols() {
		if !strings.HasPrefix(p, "socks5") {
			t.Fatalf("kept %q for tcp, want socks5 only", p)
		}
	}
	if len(g.udp) != 2 {
		t.Fatalf("kept %v for udp, want the two socks5 flavours", g.udpProtocols())
	}
	for _, p := range g.udpProtocols() {
		if !strings.HasPrefix(p, "socks5") {
			t.Fatalf("kept %q for udp, want socks5 only", p)
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

// UDP must never be attempted through a flavour that cannot carry it: with no
// udp candidate the flow leaves directly instead of erroring out.
func TestGostUDPWithoutCandidatesUsesDirect(t *testing.T) {
	g := &gostEgress{server: "127.0.0.1:1"}

	echo, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("udp listen: %v", err)
	}
	defer echo.Close()
	go func() {
		buf := make([]byte, 64)
		if _, from, err := echo.ReadFromUDP(buf); err == nil {
			_, _ = echo.WriteToUDP([]byte("ok"), from)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := g.DialContext(ctx, "udp", echo.LocalAddr().String())
	if err != nil {
		t.Fatalf("udp dial should fall back to direct: %v", err)
	}
	defer c.Close()
}

func TestGostTCPUsesDirectWhenNoCandidateRemains(t *testing.T) {
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

// The TCP order is what makes "use the fastest protocol" a measurement, and the
// sort must stay stable so equal handshake times keep the configured preference
// (socks5h before socks5 in a fake-ip deployment).
func TestSortCandidatesFastestFirst(t *testing.T) {
	a := &socks5Egress{server: "a:1080", remoteDNS: true}
	b := &socks5Egress{server: "b:1080"}
	c := &httpEgress{server: "c:3128"}

	list := []gostCandidate{
		{dialer: c, latency: 40 * time.Millisecond},
		{dialer: a, latency: 5 * time.Millisecond},
		{dialer: b, latency: 5 * time.Millisecond},
	}
	sortCandidates(list)

	if list[0].dialer != a || list[1].dialer != b {
		t.Fatalf("equal latencies lost their preference order")
	}
	if list[2].dialer != c {
		t.Fatalf("slowest candidate is not last")
	}
}

// An SSH flow must not be routed through gost's HTTP listener just because
// HTTP won the startup probe. Non-HTTP ports prefer socks5; 80/443 keep the
// measured fastest-first order.
func TestGostTCPPrefersSocks5OutsideHTTPPorts(t *testing.T) {
	socksh := &socks5Egress{server: "a:1080", remoteDNS: true}
	socks := &socks5Egress{server: "b:1080"}
	trojan := &trojanEgress{server: "c:443"}
	https := &httpEgress{server: "d:443", tlsCfg: &tls.Config{}}
	http := &httpEgress{server: "e:3128"}

	g := &gostEgress{tcp: []gostCandidate{
		{dialer: http, latency: time.Millisecond},
		{dialer: https, latency: 2 * time.Millisecond},
		{dialer: trojan, latency: 3 * time.Millisecond},
		{dialer: socksh, latency: 30 * time.Millisecond},
		{dialer: socks, latency: 40 * time.Millisecond},
	}}

	ssh := g.tcpFor("ph-vpn.dyize.com:22")
	if len(ssh) != 5 {
		t.Fatalf("ssh candidates = %d, want 5", len(ssh))
	}
	if ssh[0].dialer != socksh || ssh[1].dialer != socks {
		t.Fatalf("ssh order = %v, want socks5h then socks5", describeCandidates(ssh))
	}
	if ssh[2].dialer != http || ssh[3].dialer != https || ssh[4].dialer != trojan {
		t.Fatalf("ssh fallback order = %v, want http, https, trojan", describeCandidates(ssh))
	}

	web := g.tcpFor("example.com:443")
	if web[0].dialer != http {
		t.Fatalf("https order = %v, want the fastest candidate first", describeCandidates(web))
	}
	if plain := g.tcpFor("example.com:80"); plain[0].dialer != http {
		t.Fatalf("http order = %v, want the fastest candidate first", describeCandidates(plain))
	}
}
