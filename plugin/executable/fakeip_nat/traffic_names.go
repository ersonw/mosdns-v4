package fakeipnat

// This file keeps the runtime ip -> domain index used by the traffic watch.
// The persistent mapping tables remain the source of truth; this index is
// populated from DNS answers, from an explicit reverse lookup, and from the
// fakeip runtime table. Entries expire with record_ttl, so a watched address
// never keeps a stale name forever.

import (
	"context"
	"encoding/binary"
	"net"
	"strings"
	"sync"
	"time"

	mdns "github.com/miekg/dns"
	"go.uber.org/zap"
)

const (
	// watchNameCacheLimit bounds the runtime index independently of record_ttl.
	// A busy host can resolve far more names than one watch session needs.
	watchNameCacheLimit = 4096
	// watchNameNegativeTTL is how long a failed lookup is remembered. It keeps
	// the two-second conntrack poll from retrying the same unknown address.
	watchNameNegativeTTL = 10 * time.Minute
	// watchReverseWorkers bounds reverse DNS requests. A conntrack dump can
	// contain hundreds of unknown addresses at once.
	watchReverseWorkers = 4
	watchReverseTimeout = 4 * time.Second
)

type watchNameEntry struct {
	domain string
	seen   int64
}

// watchNameCache is a small TTL cache. The zero value is usable for tests and
// for callers that do not initialize it.
type watchNameCache struct {
	mu     sync.Mutex
	ttl    time.Duration
	clock  func() time.Time
	names  map[string]watchNameEntry
	back   map[string]int64 // failed reverse lookup, unix seconds
	dbDone map[string]int64 // real-ip table checked, unix seconds

	resolving map[string]struct{}
	sem       chan struct{}
}

func newWatchNameCache(ttl time.Duration) *watchNameCache {
	return &watchNameCache{
		ttl:       ttl,
		names:     make(map[string]watchNameEntry),
		back:      make(map[string]int64),
		dbDone:    make(map[string]int64),
		resolving: make(map[string]struct{}),
		sem:       make(chan struct{}, watchReverseWorkers),
	}
}

func (c *watchNameCache) nowUnix() int64 {
	if c.clock != nil {
		return c.clock().Unix()
	}
	return time.Now().Unix()
}

func watchNameTTLSeconds(ttl time.Duration) int64 {
	if ttl <= 0 {
		return 0
	}
	seconds := int64(ttl / time.Second)
	if seconds < 1 {
		seconds = 1
	}
	return seconds
}

func (c *watchNameCache) negativeTTLSeconds() int64 {
	seconds := int64(watchNameNegativeTTL / time.Second)
	if c.ttl > 0 {
		if ttl := watchNameTTLSeconds(c.ttl); ttl > 0 && ttl < seconds {
			return ttl
		}
	}
	return seconds
}

func normalizeWatchName(name string) string {
	name = strings.TrimSpace(name)
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return ""
	}
	return strings.ToLower(name)
}

// lookup returns a valid cached name. An expired entry is removed on the read
// path, so a missing sweep cannot leave a stale name in the message.
func (c *watchNameCache) lookup(ip string) (string, bool) {
	if c == nil {
		return "", false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.names[ip]
	if !ok {
		return "", false
	}
	if ttl := watchNameTTLSeconds(c.ttl); ttl > 0 && c.nowUnix()-e.seen >= ttl {
		delete(c.names, ip)
		return "", false
	}
	return e.domain, e.domain != ""
}

func (c *watchNameCache) remember(ip, domain string) {
	if c == nil {
		return
	}
	ip = strings.TrimSpace(ip)
	domain = normalizeWatchName(domain)
	if ip == "" || domain == "" || net.ParseIP(ip) == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.names[ip]; !ok && len(c.names) >= watchNameCacheLimit {
		for key := range c.names {
			delete(c.names, key)
			break
		}
	}
	c.names[ip] = watchNameEntry{domain: domain, seen: c.nowUnix()}
	delete(c.back, ip)
	delete(c.dbDone, ip)
}

// dbLookupAllowed avoids scanning the real-ip table again for an address that
// was already checked and had no row. A later DNS answer still repopulates the
// cache through remember.
func (c *watchNameCache) dbLookupAllowed(ip string) bool {
	if c == nil {
		return true
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	seen, ok := c.dbDone[ip]
	if !ok {
		return true
	}
	return c.nowUnix()-seen >= c.negativeTTLSeconds()
}

func (c *watchNameCache) markDBLookup(ip string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.dbDone[ip] = c.nowUnix()
}

func (c *watchNameCache) beginResolve(ip string) bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.names[ip]; ok {
		if ttl := watchNameTTLSeconds(c.ttl); ttl > 0 && c.nowUnix()-e.seen >= ttl {
			delete(c.names, ip)
		} else {
			return false
		}
	}
	if seen, ok := c.back[ip]; ok && c.nowUnix()-seen < c.negativeTTLSeconds() {
		return false
	}
	if _, ok := c.resolving[ip]; ok {
		return false
	}
	c.resolving[ip] = struct{}{}
	return true
}

func (c *watchNameCache) cancelResolve(ip string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.resolving, ip)
}

func (c *watchNameCache) finishResolve(ip, domain string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	delete(c.resolving, ip)
	if domain == "" {
		c.back[ip] = c.nowUnix()
		c.mu.Unlock()
		return
	}
	c.mu.Unlock()
	c.remember(ip, domain)
}

// reverseLookupWatchName fills a missing real-ip name asynchronously. The
// message is never blocked on DNS; the next poll sees the cached result.
func (p *FakeIPNatPlugin) reverseLookupWatchName(ip string) {
	c := p.watchNames
	if c == nil || !c.beginResolve(ip) {
		return
	}
	select {
	case c.sem <- struct{}{}:
	default:
		// The reverse pool is full. Clear the marker so the next poll can try
		// again instead of leaving the address permanently pending.
		c.cancelResolve(ip)
		return
	}
	go func() {
		defer func() { <-c.sem }()
		ctx, cancel := context.WithTimeout(context.Background(), watchReverseTimeout)
		defer cancel()
		names, err := net.DefaultResolver.LookupAddr(ctx, ip)
		domain := ""
		if err == nil {
			for _, name := range names {
				if d := normalizeWatchName(name); d != "" {
					domain = d
					break
				}
			}
		}
		if domain == "" && err != nil {
			p.L().Debug("traffic watch: reverse lookup failed",
				zap.String("ip", ip), zap.Error(err))
		}
		c.finishResolve(ip, domain)
	}()
}

// learnWatchRealIPs records the real addresses of every DNS answer the plugin
// handles. It is cheap, bounded by the cache, and makes direct/non-fakeip
// destinations nameable without a reverse lookup.
func (p *FakeIPNatPlugin) learnWatchRealIPs(domain string, ips []string) {
	if p.watchNames == nil || len(ips) == 0 {
		return
	}
	for _, ip := range ips {
		if p.isFakeAddrString(ip) {
			continue
		}
		p.watchNames.remember(ip, domain)
	}
}

// parseWatchDNSNames extracts A answer names from one IPv4 UDP DNS packet. It
// only returns answers with a real IPv4 address; the fakeip runtime already
// has its own fake-ip mapping.
func parseWatchDNSNames(pkt []byte) map[string]string {
	if len(pkt) < ipv4HeaderMinLen || pkt[0]>>4 != 4 || pkt[9] != protoUDP {
		return nil
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < ipv4HeaderMinLen || len(pkt) < ihl+udpHeaderLen {
		return nil
	}
	total := int(binary.BigEndian.Uint16(pkt[2:4]))
	if total < ihl+udpHeaderLen || total > len(pkt) {
		return nil
	}
	if binary.BigEndian.Uint16(pkt[6:8])&ipv4FragMask != 0 {
		return nil
	}
	srcPort := binary.BigEndian.Uint16(pkt[ihl : ihl+2])
	dstPort := binary.BigEndian.Uint16(pkt[ihl+2 : ihl+4])
	if srcPort != 53 && dstPort != 53 {
		return nil
	}
	udpLen := int(binary.BigEndian.Uint16(pkt[ihl+4 : ihl+6]))
	if udpLen < udpHeaderLen || ihl+udpLen > total {
		return nil
	}
	var msg mdns.Msg
	if err := msg.Unpack(pkt[ihl+udpHeaderLen : ihl+udpLen]); err != nil {
		return nil
	}
	if len(msg.Question) == 0 {
		return nil
	}
	qname := normalizeWatchName(msg.Question[0].Name)
	if qname == "" {
		return nil
	}
	names := make(map[string]string)
	for _, ans := range msg.Answer {
		a, ok := ans.(*mdns.A)
		if !ok || a.A == nil {
			continue
		}
		name := normalizeWatchName(a.Hdr.Name)
		if name == "" {
			name = qname
		}
		names[a.A.String()] = name
	}
	if len(names) == 0 {
		return nil
	}
	return names
}

// observeTunDNS learns names from DNS packets that pass through the tun reader,
// including packets the ownership check later drops. It never records a
// traffic event.
func (p *FakeIPNatPlugin) observeTunDNS(pkt []byte) {
	if p.watch == nil || p.watchNames == nil || !p.watch.active() {
		return
	}
	for ip, domain := range parseWatchDNSNames(pkt) {
		if p.isFakeAddrString(ip) {
			continue
		}
		p.watchNames.remember(ip, domain)
	}
}
