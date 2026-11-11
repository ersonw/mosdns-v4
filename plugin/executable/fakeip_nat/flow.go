package fakeipnat

// This file owns the connection bookkeeping of the tun data path: a client
// packet to a fake ip is redirected to the real ip with the fake ip as its new
// source, and the reply has to be mapped back to the client. Everything that
// identifies a flow lives here.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"go.uber.org/zap"
)

const (
	defaultConntrackSize = 8192
	defaultConntrackTTL  = 2 * time.Minute
	natPortMin           = 1024
	natPortMax           = 65535
	// The first allocated port keeps clear of the well known range.
	natPortStart = 12000
)

var (
	errNoFakeIPMapping = errors.New("fake ip is not allocated")
	errNoRealIP        = errors.New("no real ip recorded for domain")
	errConntrackFull   = errors.New("conntrack table is full")
)

// forwardKey identifies a client -> fake ip flow. It is what the client sends.
type forwardKey struct {
	proto      uint8
	fake       netip.Addr
	client     netip.Addr
	clientPort uint16
	serverPort uint16
}

// reverseKey identifies the reply of a flow: it arrives addressed to the fake
// ip, from the real ip, on the port the plugin picked as the new source port.
type reverseKey struct {
	proto      uint8
	fake       netip.Addr
	server     netip.Addr
	serverPort uint16
	natPort    uint16
}

type connEntry struct {
	fwd      forwardKey
	rev      reverseKey
	lastSeen time.Time
}

type conntrack struct {
	mu       sync.Mutex
	fwd      map[forwardKey]*connEntry
	rev      map[reverseKey]*connEntry
	ports    map[uint16]struct{} // nat source ports currently in use
	nextPort uint16
	ttl      time.Duration
	max      int
}

func newConntrack(max int, ttl time.Duration) *conntrack {
	return &conntrack{
		fwd:      make(map[forwardKey]*connEntry),
		rev:      make(map[reverseKey]*connEntry),
		ports:    make(map[uint16]struct{}),
		nextPort: natPortStart,
		ttl:      ttl,
		max:      max,
	}
}

// forward returns the source port to use towards the real ip, creating the flow
// on first sight. The same client tuple always gets the same port.
func (c *conntrack) forward(key forwardKey, server netip.Addr) (uint16, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	c.sweepLocked(now)

	if e, ok := c.fwd[key]; ok {
		e.lastSeen = now
		return e.rev.natPort, nil
	}
	if len(c.fwd) >= c.max {
		return 0, errConntrackFull
	}

	port, err := c.allocPortLocked()
	if err != nil {
		return 0, err
	}
	e := &connEntry{
		fwd: key,
		rev: reverseKey{
			proto:      key.proto,
			fake:       key.fake,
			server:     server,
			serverPort: key.serverPort,
			natPort:    port,
		},
		lastSeen: now,
	}
	c.fwd[key] = e
	c.rev[e.rev] = e
	c.ports[port] = struct{}{}
	return port, nil
}

// clientTarget is the original client side of a tracked flow.
type clientTarget struct {
	client netip.Addr
	port   uint16
	fake   netip.Addr
}

func (c *conntrack) reverse(key reverseKey) (clientTarget, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	e, ok := c.rev[key]
	if !ok {
		return clientTarget{}, false
	}
	e.lastSeen = time.Now()
	return clientTarget{client: e.fwd.client, port: e.fwd.clientPort, fake: e.fwd.fake}, true
}

func (c *conntrack) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.fwd)
}

// expire removes idle flows; it is called from forward so a busy plugin keeps
// its table bounded without a background goroutine.
func (c *conntrack) expire(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sweepLocked(time.Now().Add(d))
}

func (c *conntrack) sweepLocked(now time.Time) {
	for k, e := range c.rev {
		if now.Sub(e.lastSeen) > c.ttl {
			delete(c.rev, k)
			delete(c.fwd, e.fwd)
			delete(c.ports, k.natPort)
		}
	}
}

func (c *conntrack) allocPortLocked() (uint16, error) {
	if len(c.ports) >= natPortMax-natPortMin {
		return 0, errConntrackFull
	}
	for i := 0; i < natPortMax-natPortMin; i++ {
		port := c.nextPort
		c.nextPort++
		if c.nextPort < natPortMin || c.nextPort >= natPortMax {
			c.nextPort = natPortMin
		}
		if port < natPortMin || port >= natPortMax {
			continue
		}
		if _, used := c.ports[port]; used {
			continue
		}
		return port, nil
	}
	return 0, errConntrackFull
}

// domainForFakeIP reverses the mapping table entry of a fake ip. The runtime
// table answers first; SQLite is only consulted on a miss, and the result is
// cached back into the runtime table.
func (p *FakeIPNatPlugin) domainForFakeIP(ctx context.Context, fakeIP string) (string, error) {
	if p.runtime != nil {
		if domain, ok := p.runtime.domainOf(fakeIP); ok {
			// A row written by an older build, or by an upstream that answered
			// with a fake address, can name an address of this range as the
			// "domain". Handing that to an outlet makes it dial the fake ip.
			if !p.isFakeAddrString(domain) {
				return domain, nil
			}
			p.L().Warn("fakeip nat: mapping names a fake ip as its domain",
				zap.String("fake_ip", fakeIP), zap.String("domain", domain))
		}
	}
	var domain string
	err := p.db.QueryRowContext(ctx,
		"SELECT domain FROM "+p.mapTable+" WHERE fake_ip = ?", fakeIP).Scan(&domain)
	if errors.Is(err, sql.ErrNoRows) {
		p.L().Debug("fakeip nat: fake ip has no mapping", zap.String("fake_ip", fakeIP))
		return "", fmt.Errorf("%w: %s", errNoFakeIPMapping, fakeIP)
	}
	if err != nil {
		p.L().Debug("fakeip nat: lookup fake ip failed", zap.String("fake_ip", fakeIP), zap.Error(err))
		return "", fmt.Errorf("lookup fake ip %s: %w", fakeIP, err)
	}
	if p.isFakeAddrString(domain) {
		p.L().Warn("fakeip nat: stored mapping names a fake ip as its domain",
			zap.String("fake_ip", fakeIP), zap.String("domain", domain))
		return "", fmt.Errorf("%w: %s (domain is inside the fake range)", errNoFakeIPMapping, fakeIP)
	}
	if p.runtime != nil {
		p.runtime.put(domain, fakeIP)
	}
	p.L().Debug("fakeip nat: fake ip mapped", zap.String("fake_ip", fakeIP), zap.String("domain", domain))
	return domain, nil
}

// primaryRealIP picks the most recently observed real ip of a domain. Rows
// inside the plugin's own range are skipped: an upstream that answered with a
// fake address, or a row written before this guard existed, would otherwise
// become the destination every outlet is told to reach.
func (p *FakeIPNatPlugin) primaryRealIP(ctx context.Context, domain string) (netip.Addr, error) {
	const scanLimit = 64
	rows, err := p.db.QueryContext(ctx,
		"SELECT real_ip FROM "+p.ipTable+" WHERE domain = ? ORDER BY last_seen DESC LIMIT ?",
		domain, scanLimit)
	if err != nil {
		p.L().Debug("fakeip nat: lookup real ip failed", zap.String("domain", domain), zap.Error(err))
		return netip.Addr{}, fmt.Errorf("lookup real ip of %s: %w", domain, err)
	}
	defer rows.Close()

	var skipped []string
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			p.L().Debug("fakeip nat: scan real ip failed", zap.String("domain", domain), zap.Error(err))
			return netip.Addr{}, fmt.Errorf("scan real ip of %s: %w", domain, err)
		}
		if p.isFakeAddrString(raw) {
			skipped = append(skipped, raw)
			continue
		}
		addr, err := netip.ParseAddr(raw)
		if err != nil || !addr.Is4() {
			p.L().Debug("fakeip nat: stored real ip is invalid",
				zap.String("domain", domain), zap.String("real_ip", raw))
			continue
		}
		p.L().Debug("fakeip nat: real ip selected", zap.String("domain", domain), zap.String("real_ip", addr.String()))
		return addr, nil
	}
	if err := rows.Err(); err != nil {
		return netip.Addr{}, fmt.Errorf("iterate real ips of %s: %w", domain, err)
	}
	if len(skipped) > 0 {
		p.L().Warn("fakeip nat: every recorded real ip is inside the fake range",
			zap.String("domain", domain), zap.Strings("fake_ips", skipped))
	}
	p.L().Debug("fakeip nat: domain has no recorded real ip", zap.String("domain", domain))
	return netip.Addr{}, fmt.Errorf("%w: %s", errNoRealIP, domain)
}

// forwardPacket turns a client -> fake ip packet into the outbound packet:
// destination becomes the real ip, source becomes the fake ip (so the reply is
// routed back to the tun device), and the source port is translated to a free
// one. It returns the real ip the flow was sent to.
func (p *FakeIPNatPlugin) forwardPacket(ctx context.Context, pkt *packetView) (netip.Addr, error) {
	fakeIP := pkt.dst
	if !p.prefix.Contains(fakeIP) {
		return netip.Addr{}, fmt.Errorf("destination %s is outside %s", fakeIP, p.cidr)
	}

	domain, err := p.domainForFakeIP(ctx, fakeIP.String())
	if err != nil {
		return netip.Addr{}, err
	}
	realIP, err := p.primaryRealIP(ctx, domain)
	if err != nil {
		return netip.Addr{}, err
	}

	port, err := p.conn.forward(forwardKey{
		proto:      pkt.proto,
		fake:       fakeIP,
		client:     pkt.src,
		clientPort: pkt.srcPort,
		serverPort: pkt.dstPort,
	}, realIP)
	if err != nil {
		return netip.Addr{}, err
	}

	pkt.setSrc(fakeIP)
	pkt.setDst(realIP)
	pkt.setSrcPort(port)
	pkt.recomputeChecksums()
	return realIP, nil
}

// reversePacket rewrites a reply packet back towards the client: source becomes
// the fake ip the client targeted, destination becomes the client address and
// port. It reports whether the packet belongs to a tracked flow.
func (p *FakeIPNatPlugin) reversePacket(pkt *packetView) (bool, error) {
	target, ok := p.conn.reverse(reverseKey{
		proto:      pkt.proto,
		fake:       pkt.dst,
		server:     pkt.src,
		serverPort: pkt.srcPort,
		natPort:    pkt.dstPort,
	})
	if !ok {
		return false, nil
	}

	pkt.setSrc(target.fake)
	pkt.setDst(target.client)
	pkt.setDstPort(target.port)
	pkt.recomputeChecksums()
	return true, nil
}
