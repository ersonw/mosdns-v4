package fakeipnat

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestWatchNameCacheExpiresWithRecordTTL(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	c := newWatchNameCache(2 * time.Second)
	c.clock = func() time.Time { return now }
	c.remember("203.0.113.9", "Example.COM.")
	if domain, ok := c.lookup("203.0.113.9"); !ok || domain != "example.com" {
		t.Fatalf("lookup = %q, %v", domain, ok)
	}
	now = now.Add(time.Second)
	if _, ok := c.lookup("203.0.113.9"); !ok {
		t.Fatal("entry expired before record_ttl")
	}
	now = now.Add(time.Second)
	if domain, ok := c.lookup("203.0.113.9"); ok {
		t.Fatalf("expired entry still visible: %q", domain)
	}
}

func TestParseWatchDNSNames(t *testing.T) {
	msg := new(dns.Msg)
	msg.SetQuestion("direct.example.", dns.TypeA)
	msg.Response = true
	msg.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: "direct.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
		A:   net.ParseIP("203.0.113.10").To4(),
	}}
	payload, err := msg.Pack()
	if err != nil {
		t.Fatalf("pack dns: %v", err)
	}
	names := parseWatchDNSNames(buildWatchDNSV4Packet(payload))
	if names["203.0.113.10"] != "direct.example" {
		t.Fatalf("names = %+v", names)
	}
}

func TestObserveTunDNSLearnsName(t *testing.T) {
	p := newWatchTestPlugin()
	p.watchNames = newWatchNameCache(0)
	p.watch.add("192.0.2.10")
	msg := new(dns.Msg)
	msg.SetQuestion("direct.example.", dns.TypeA)
	msg.Response = true
	msg.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: "direct.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
		A:   net.ParseIP("203.0.113.10").To4(),
	}}
	payload, err := msg.Pack()
	if err != nil {
		t.Fatalf("pack dns: %v", err)
	}
	p.observeTunDNS(buildWatchDNSV4Packet(payload))
	if domain, ok := p.watchNames.lookup("203.0.113.10"); !ok || domain != "direct.example" {
		t.Fatalf("lookup = %q, %v", domain, ok)
	}
}

func TestDescribeWatchDestinationUsesRealNameCache(t *testing.T) {
	p := newWatchTestPlugin()
	p.watchNames = newWatchNameCache(0)
	p.watchNames.remember("203.0.113.10", "direct.example")
	domain, fakeIP, destination := p.describeWatchDestination(context.Background(), "203.0.113.10", "", false)
	if domain != "direct.example" || fakeIP != "" || destination != "203.0.113.10" {
		t.Fatalf("domain=%q fake=%q dest=%q", domain, fakeIP, destination)
	}
}

func TestDomainForRealIPUsesSQLiteFallback(t *testing.T) {
	p := newTestPlugin(t, "198.18.0.0/16")
	if _, err := p.db.Exec(
		"INSERT INTO "+p.ipTable+" (domain, real_ip, last_seen) VALUES (?, ?, ?)",
		"direct.example", "203.0.113.10", time.Now().Unix()); err != nil {
		t.Fatalf("insert real ip: %v", err)
	}
	domain, err := p.domainForRealIP(context.Background(), "203.0.113.10")
	if err != nil {
		t.Fatalf("domainForRealIP: %v", err)
	}
	if domain != "direct.example" {
		t.Fatalf("domain = %q", domain)
	}
	if _, ok := p.runtime.domainOfReal("203.0.113.10"); !ok {
		t.Fatal("SQLite fallback was not cached into the runtime table")
	}
}

func buildWatchDNSV4Packet(payload []byte) []byte {
	buf := make([]byte, ipv4HeaderMinLen+udpHeaderLen+len(payload))
	buf[0] = 0x45
	binary.BigEndian.PutUint16(buf[2:4], uint16(len(buf)))
	buf[8] = 64
	buf[9] = protoUDP
	copy(buf[12:16], net.ParseIP("192.0.2.53").To4())
	copy(buf[16:20], net.ParseIP("192.0.2.10").To4())
	binary.BigEndian.PutUint16(buf[20:22], 53)
	binary.BigEndian.PutUint16(buf[22:24], 40000)
	binary.BigEndian.PutUint16(buf[24:26], uint16(udpHeaderLen+len(payload)))
	copy(buf[ipv4HeaderMinLen+udpHeaderLen:], payload)
	return buf
}
