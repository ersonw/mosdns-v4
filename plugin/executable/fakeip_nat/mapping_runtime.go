package fakeipnat

// This file keeps the domain <-> fake ip relation in memory. SQLite stays the
// source of truth across restarts, but the runtime table is what the data path
// consults, so a flow never has to wait on a query. It is restored once at
// startup and kept in sync on every allocation.
//
// The NAT data path has a second source of truth: the nftables dnat map can
// still hold entries whose database row was lost (crash, manual nft edit).
// Startup therefore reconciles the two: entries the database knows but the map
// is missing are re-applied, and fake ips only the map knows are reserved so
// the allocator never hands them out twice.

import (
	"context"
	"fmt"
	"sync"

	"go.uber.org/zap"
)

// runtimeMap is the in-memory mirror of "<prefix>_mapping".
type runtimeMap struct {
	mu       sync.RWMutex
	byDomain map[string]string // domain -> fake ip
	byFake   map[string]string // fake ip -> domain ("" means reserved, owner unknown)
}

func newRuntimeMap() *runtimeMap {
	return &runtimeMap{
		byDomain: make(map[string]string),
		byFake:   make(map[string]string),
	}
}

// put records a domain <-> fake ip relation, replacing a stale one on either
// side so the two indexes never disagree.
func (m *runtimeMap) put(domain, fakeIP string) {
	if domain == "" || fakeIP == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if old, ok := m.byDomain[domain]; ok && old != fakeIP {
		delete(m.byFake, old)
	}
	if oldDomain, ok := m.byFake[fakeIP]; ok && oldDomain != domain {
		if oldDomain != "" {
			delete(m.byDomain, oldDomain)
		}
	}
	m.byDomain[domain] = fakeIP
	m.byFake[fakeIP] = domain
}

// remove drops the relation owned by domain. The fake ip is released with it,
// so the allocator may hand it to another domain on the next allocation.
// clear drops every relation, including firewall-only reservations.
func (m *runtimeMap) clear() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.byDomain = make(map[string]string)
	m.byFake = make(map[string]string)
}

func (m *runtimeMap) remove(domain string) {
	if domain == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	fakeIP, ok := m.byDomain[domain]
	if !ok {
		return
	}
	delete(m.byDomain, domain)
	if m.byFake[fakeIP] == domain {
		delete(m.byFake, fakeIP)
	}
}

// reserve keeps a fake ip that only the firewall map knows about: it is in use,
// but no domain can be attached to it.
func (m *runtimeMap) reserve(fakeIP string) {
	if fakeIP == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.byFake[fakeIP]; !ok {
		m.byFake[fakeIP] = ""
	}
}

func (m *runtimeMap) domainOf(fakeIP string) (string, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	domain, ok := m.byFake[fakeIP]
	if !ok || domain == "" {
		return "", false
	}
	return domain, true
}

func (m *runtimeMap) fakeOf(domain string) (string, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	fakeIP, ok := m.byDomain[domain]
	return fakeIP, ok
}

// isReserved reports whether the address is known to be in use but has no
// domain attached (firewall-only entry).
func (m *runtimeMap) isReserved(fakeIP string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	domain, ok := m.byFake[fakeIP]
	return ok && domain == ""
}

// snapshotByDomain returns a copy so callers can iterate without holding the
// read lock while they talk to SQLite or nft.
func (m *runtimeMap) snapshotByDomain() map[string]string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make(map[string]string, len(m.byDomain))
	for domain, fakeIP := range m.byDomain {
		out[domain] = fakeIP
	}
	return out
}

func (m *runtimeMap) size() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.byDomain)
}

// restoreRuntimeMappings fills the runtime table from SQLite. Rows still
// carrying the pending placeholder are skipped: they get a real address on
// their first allocation.
func (p *FakeIPNatPlugin) restoreRuntimeMappings(ctx context.Context) error {
	query := fmt.Sprintf("SELECT domain, fake_ip FROM %s", p.mapTable)
	rows, err := p.db.QueryContext(ctx, query)
	if err != nil {
		return fmt.Errorf("query mappings: %w", err)
	}
	defer rows.Close()

	restored, pending := 0, 0
	for rows.Next() {
		var domain, fakeIP string
		if err := rows.Scan(&domain, &fakeIP); err != nil {
			return fmt.Errorf("scan mapping: %w", err)
		}
		if fakeIP == pendingFakeIP {
			pending++
			continue
		}
		p.runtime.put(domain, fakeIP)
		restored++
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate mappings: %w", err)
	}
	p.L().Info("fakeip nat: runtime mapping table restored",
		zap.Int("entries", restored), zap.Int("pending", pending), zap.String("source", "sqlite"))
	return nil
}

// reconcileFirewallMappings makes the NAT data path consistent with the runtime
// table: database rows the nft map is missing are re-applied with their newest
// real ip, and fake ips that only the map knows are reserved.
func (p *FakeIPNatPlugin) reconcileFirewallMappings(ctx context.Context) {
	table := p.nftTableName()
	firewall := p.nftMappings(ctx, table)
	if firewall == nil {
		p.L().Debug("fakeip nat: firewall mapping unavailable, reconciliation skipped",
			zap.String("nft_table", table))
		return
	}

	refilled := 0
	for domain, fakeIP := range p.runtime.snapshotByDomain() {
		if _, ok := firewall[fakeIP]; ok {
			continue
		}
		real, err := p.primaryRealIP(ctx, domain)
		if err != nil {
			p.L().Debug("fakeip nat: mapping without a real ip cannot be refilled",
				zap.String("domain", domain), zap.String("fake_ip", fakeIP))
			continue
		}
		if _, err := p.runner.Run(ctx, "nft", "add", "element", "ip", table, nftMapName,
			"{ "+fakeIP+" : "+real.String()+" }"); err != nil {
			p.L().Warn("fakeip nat: refill firewall mapping failed",
				zap.String("domain", domain), zap.String("fake_ip", fakeIP), zap.String("real_ip", real.String()), zap.Error(err))
			continue
		}
		refilled++
		p.L().Debug("fakeip nat: firewall mapping refilled",
			zap.String("domain", domain), zap.String("fake_ip", fakeIP), zap.String("real_ip", real.String()))
	}

	reserved := 0
	for fakeIP := range firewall {
		if _, ok := p.runtime.domainOf(fakeIP); ok {
			continue
		}
		if p.runtime.isReserved(fakeIP) {
			continue
		}
		p.runtime.reserve(fakeIP)
		reserved++
		p.L().Debug("fakeip nat: firewall mapping without a database row reserved", zap.String("fake_ip", fakeIP))
	}

	p.L().Info("fakeip nat: firewall mapping reconciled",
		zap.String("nft_table", table), zap.Int("firewall_entries", len(firewall)),
		zap.Int("refilled", refilled), zap.Int("reserved", reserved))
}
