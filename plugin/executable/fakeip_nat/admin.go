/*
 * Copyright (C) 2020-2022, IrineSistiana
 *
 * This file is part of mosdns.
 *
 * mosdns is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * mosdns is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

// This file exposes the read/write operations that an external control
// surface (for example the telegram_bot plugin) needs. They are deliberately
// small and synchronous: callers are human-driven, not on the DNS hot path.

package fakeipnat

import (
	"context"
	"database/sql"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	fakeipadmin "github.com/ersonw/mosdns-v4/pkg/fakeip_admin"
	"go.uber.org/zap"
)

// MappingEntry, MappingStats and PurgeReport are aliases of the shared admin
// types, so callers can use either the concrete plugin or pkg/fakeip_admin.
type (
	MappingEntry = fakeipadmin.Entry
	MappingStats = fakeipadmin.Stats
	PurgeReport  = fakeipadmin.PurgeReport
)

// The plugin is the reference implementation of both admin contracts; a build
// failure here means a control surface lost a capability it relies on.
var (
	_ fakeipadmin.Admin      = (*FakeIPNatPlugin)(nil)
	_ fakeipadmin.PurgeAdmin = (*FakeIPNatPlugin)(nil)
)

const adminListLimit = 500

// AdminListMappings returns the most recently created mappings, newest first.
func (p *FakeIPNatPlugin) AdminListMappings(ctx context.Context, limit int) ([]MappingEntry, error) {
	if limit <= 0 {
		limit = 20
	}
	if limit > adminListLimit {
		limit = adminListLimit
	}
	rows, err := p.db.QueryContext(ctx,
		`SELECT domain, fake_ip, created_at FROM `+p.mapTable+` ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("list mappings: %w", err)
	}
	defer rows.Close()

	var out []MappingEntry
	for rows.Next() {
		var e MappingEntry
		if err := rows.Scan(&e.Domain, &e.FakeIP, &e.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan mapping: %w", err)
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list mappings: %w", err)
	}
	return out, nil
}

// AdminLookupDomain returns the mapping of one domain. The bool is false when
// the domain has never been seen.
func (p *FakeIPNatPlugin) AdminLookupDomain(ctx context.Context, domain string) (*MappingEntry, bool, error) {
	return p.adminLookup(ctx, "domain", domain)
}

// AdminLookupFakeIP returns the mapping that owns a fake ip.
func (p *FakeIPNatPlugin) AdminLookupFakeIP(ctx context.Context, fakeIP string) (*MappingEntry, bool, error) {
	return p.adminLookup(ctx, "fake_ip", fakeIP)
}

func (p *FakeIPNatPlugin) adminLookup(ctx context.Context, column, value string) (*MappingEntry, bool, error) {
	var e MappingEntry
	err := p.db.QueryRowContext(ctx,
		`SELECT domain, fake_ip, created_at FROM `+p.mapTable+` WHERE `+column+` = ? LIMIT 1`, value).
		Scan(&e.Domain, &e.FakeIP, &e.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("lookup %s: %w", column, err)
	}
	return &e, true, nil
}

// AdminDeleteDomain drops one mapping from SQLite, the in-memory table and,
// on the NAT path, the nftables dnat map. The next query for the domain
// allocates a fresh fake ip.
func (p *FakeIPNatPlugin) AdminDeleteDomain(ctx context.Context, domain string) (bool, error) {
	entry, ok, err := p.AdminLookupDomain(ctx, domain)
	if err != nil {
		return false, err
	}
	if !ok {
		return false, nil
	}

	res, err := p.db.ExecContext(ctx, `DELETE FROM `+p.mapTable+` WHERE domain = ?`, domain)
	if err != nil {
		return false, fmt.Errorf("delete mapping: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return false, nil
	}

	p.removeRuntimeMapping(domain)
	p.removeNFTMapping(ctx, entry.FakeIP)
	p.L().Info("mapping deleted by admin", zap.String("domain", domain), zap.String("fake_ip", entry.FakeIP))
	return true, nil
}

// AdminPurgeDomain removes every row that could still influence how the domain
// resolves: its own mapping, the mappings of its subdomains, the real ips the
// plane learned for all of them and the access log rows that reference them.
// The in-memory table and the nft dnat elements go with the mappings, so the
// next query starts from a clean state instead of reusing a stale fake ip or a
// stale real destination.
//
// Subdomains are included because a provider rule matches by suffix: deleting
// "example.com" has to take "a.example.com" with it, otherwise a name that no
// longer has a rule keeps the answer learned under the old one.
func (p *FakeIPNatPlugin) AdminPurgeDomain(ctx context.Context, domain string) (fakeipadmin.PurgeReport, error) {
	var rep fakeipadmin.PurgeReport
	domain = normalizePurgeDomain(domain)
	if domain == "" {
		return rep, fmt.Errorf("empty domain")
	}
	like := "%." + domain

	// Collect the fake ips before deleting the rows: the nft elements are keyed
	// by fake ip, and after the delete there is nothing left to read them from.
	fakeIPs, domains, err := p.purgeCandidates(ctx, domain, like)
	if err != nil {
		return rep, err
	}

	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return rep, fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback()

	mappings, err := deleteByDomain(ctx, tx, p.mapTable, domain, like)
	if err != nil {
		return rep, fmt.Errorf("delete mappings: %w", err)
	}
	realIPs, err := deleteByDomain(ctx, tx, p.ipTable, domain, like)
	if err != nil {
		return rep, fmt.Errorf("delete real ips: %w", err)
	}
	access, err := deleteByDomain(ctx, tx, p.accessTable, domain, like)
	if err != nil {
		return rep, fmt.Errorf("delete access rows: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return rep, fmt.Errorf("commit: %w", err)
	}

	for _, name := range domains {
		p.removeRuntimeMapping(name)
	}
	for _, fakeIP := range fakeIPs {
		p.removeNFTMapping(ctx, fakeIP)
	}

	rep.Mappings = int(mappings)
	rep.RealIPs = int(realIPs)
	rep.Access = int(access)
	rep.Domains = domains
	p.L().Info("domain purged by admin",
		zap.String("domain", domain),
		zap.Int64("mappings", mappings),
		zap.Int64("real_ips", realIPs),
		zap.Int64("access_rows", access),
		zap.Strings("domains", domains))
	return rep, nil
}

// purgeCandidates returns the fake ips and the domain names the purge will drop.
func (p *FakeIPNatPlugin) purgeCandidates(ctx context.Context, domain, like string) ([]string, []string, error) {
	rows, err := p.db.QueryContext(ctx,
		`SELECT domain, fake_ip FROM `+p.mapTable+` WHERE `+purgeWhere, domain, like)
	if err != nil {
		return nil, nil, fmt.Errorf("select mappings: %w", err)
	}
	defer rows.Close()

	var fakeIPs []string
	seen := make(map[string]bool)
	for rows.Next() {
		var name, fakeIP string
		if err := rows.Scan(&name, &fakeIP); err != nil {
			return nil, nil, fmt.Errorf("scan mapping: %w", err)
		}
		if fakeIP != "" && fakeIP != pendingFakeIP {
			fakeIPs = append(fakeIPs, fakeIP)
		}
		seen[name] = true
	}
	if err := rows.Err(); err != nil {
		return nil, nil, fmt.Errorf("iterate mappings: %w", err)
	}

	// A realip-mode run records addresses without a mapping of its own, and a
	// domain can outlive its mapping row, so the real ip table is scanned too.
	realRows, err := p.db.QueryContext(ctx,
		`SELECT DISTINCT domain FROM `+p.ipTable+` WHERE `+purgeWhere, domain, like)
	if err != nil {
		return nil, nil, fmt.Errorf("select real ip domains: %w", err)
	}
	defer realRows.Close()
	for realRows.Next() {
		var name string
		if err := realRows.Scan(&name); err != nil {
			return nil, nil, fmt.Errorf("scan real ip domain: %w", err)
		}
		seen[name] = true
	}
	if err := realRows.Err(); err != nil {
		return nil, nil, fmt.Errorf("iterate real ip domains: %w", err)
	}

	domains := make([]string, 0, len(seen))
	for name := range seen {
		domains = append(domains, name)
	}
	sort.Strings(domains)
	return fakeIPs, domains, nil
}

// purgeWhere matches the domain itself and every subdomain of it, case
// insensitively: the mapping table stores whatever name the query carried.
const purgeWhere = `LOWER(domain) = ? OR LOWER(domain) LIKE ?`

func deleteByDomain(ctx context.Context, tx *sql.Tx, table, domain, like string) (int64, error) {
	res, err := tx.ExecContext(ctx, `DELETE FROM `+table+` WHERE `+purgeWhere, domain, like)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func normalizePurgeDomain(domain string) string {
	return strings.ToLower(strings.TrimSpace(strings.TrimSuffix(domain, ".")))
}

// AdminClearMappings drops every mapping. It is meant for a deliberate reset:
// in-flight DNS answers keep working until the client re-resolves.
func (p *FakeIPNatPlugin) AdminClearMappings(ctx context.Context) (int64, error) {
	res, err := p.db.ExecContext(ctx, `DELETE FROM `+p.mapTable)
	if err != nil {
		return 0, fmt.Errorf("clear mappings: %w", err)
	}
	n, _ := res.RowsAffected()

	// A reset has to leave nothing that could steer the next resolution: the
	// learned addresses and the visit records go with the mappings.
	if _, err := p.db.ExecContext(ctx, `DELETE FROM `+p.ipTable); err != nil {
		return n, fmt.Errorf("clear real ips: %w", err)
	}
	if _, err := p.db.ExecContext(ctx, `DELETE FROM `+p.accessTable); err != nil {
		return n, fmt.Errorf("clear access rows: %w", err)
	}

	if p.runtime != nil {
		p.runtime.clear()
	}
	if !p.useTun {
		// The dnat map is rebuilt from the database, so drop the elements
		// instead of leaving them pointing at stale real ips.
		if _, err := p.runner.Run(ctx, "nft", "flush", "map", "ip", p.nftTableName(), nftMapName); err != nil {
			p.L().Debug("flush nft map failed", zap.String("table", p.nftTableName()), zap.Error(err))
		}
	}
	p.L().Info("all mappings cleared by admin", zap.Int64("rows", n))
	return n, nil
}

// AdminStats returns the aggregate counters shown by the control surface.
func (p *FakeIPNatPlugin) AdminStats(ctx context.Context) (MappingStats, error) {
	var s MappingStats
	if err := p.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM `+p.mapTable).Scan(&s.Mappings); err != nil {
		return s, fmt.Errorf("count mappings: %w", err)
	}
	if err := p.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM `+p.mapTable+` WHERE fake_ip = ?`, pendingFakeIP).Scan(&s.Pending); err != nil {
		return s, fmt.Errorf("count pending: %w", err)
	}
	if err := p.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM `+p.ipTable).Scan(&s.RealIPs); err != nil {
		return s, fmt.Errorf("count real ips: %w", err)
	}
	if p.runtime != nil {
		s.Runtime = p.runtime.size()
	}
	return s, nil
}

// AdminPutMapping creates or replaces the mapping of one domain. The fake ip
// must be inside the configured range and must not be the device address of
// the tun path. On the NAT path the nft element is rewritten as well, so an
// operator can pin a domain without waiting for a DNS query.
func (p *FakeIPNatPlugin) AdminPutMapping(ctx context.Context, domain, fakeIP string) error {
	domain = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(domain, ".")))
	if domain == "" {
		return fmt.Errorf("empty domain")
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(fakeIP))
	if err != nil || !addr.Is4() {
		return fmt.Errorf("invalid ipv4 address %q", fakeIP)
	}
	if !p.prefix.Contains(addr) {
		return fmt.Errorf("%s is outside %s", addr, p.prefix)
	}
	if p.useTun && addr == p.reservedAddr() {
		return fmt.Errorf("%s is the tun device address", addr)
	}

	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback()

	// fake_ip is unique: the previous owner has to give it up before the new
	// domain can take it, otherwise the insert conflicts.
	var previousOwner string
	if err := tx.QueryRowContext(ctx,
		`SELECT domain FROM `+p.mapTable+` WHERE fake_ip = ? AND domain <> ? LIMIT 1`,
		addr.String(), domain).Scan(&previousOwner); err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("find previous owner: %w", err)
	}
	if previousOwner != "" {
		if _, err := tx.ExecContext(ctx,
			`DELETE FROM `+p.mapTable+` WHERE fake_ip = ? AND domain <> ?`,
			addr.String(), domain); err != nil {
			return fmt.Errorf("release fake ip: %w", err)
		}
	}

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO `+p.mapTable+` (domain, fake_ip, created_at) VALUES (?, ?, ?)
		 ON CONFLICT(domain) DO UPDATE SET fake_ip = excluded.fake_ip`,
		domain, addr.String(), time.Now().Unix()); err != nil {
		return fmt.Errorf("upsert mapping: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}

	if previousOwner != "" {
		p.removeRuntimeMapping(previousOwner)
	}
	if p.runtime != nil {
		p.runtime.put(domain, addr.String())
	}

	if !p.useTun {
		if real, err := p.primaryRealIP(ctx, domain); err == nil {
			if _, err := p.runner.Run(ctx, "nft", "add", "element", "ip", p.nftTableName(), nftMapName,
				"{ "+addr.String()+" : "+real.String()+" }"); err != nil {
				// Best effort: the next firewall sync reconciles the map.
				p.L().Warn("write nft mapping failed",
					zap.String("table", p.nftTableName()), zap.String("fake_ip", addr.String()), zap.Error(err))
			}
		}
	}
	p.L().Info("mapping written by admin",
		zap.String("domain", domain), zap.String("fake_ip", addr.String()))
	return nil
}

func (p *FakeIPNatPlugin) removeRuntimeMapping(domain string) {
	if p.runtime == nil {
		return
	}
	p.runtime.remove(domain)
}

func (p *FakeIPNatPlugin) removeNFTMapping(ctx context.Context, fakeIP string) {
	if p.useTun || fakeIP == "" || fakeIP == pendingFakeIP {
		return
	}
	if _, err := p.runner.Run(ctx, "nft", "delete", "element", "ip", p.nftTableName(), nftMapName, "{ "+fakeIP+" }"); err != nil {
		// Best effort: the element may already be gone, and the next sync
		// reconciles the map anyway.
		p.L().Debug("delete nft mapping failed",
			zap.String("table", p.nftTableName()), zap.String("fake_ip", fakeIP), zap.Error(err))
	}
}
