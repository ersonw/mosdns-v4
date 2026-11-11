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
	"strings"
	"time"

	fakeipadmin "github.com/ersonw/mosdns-v4/pkg/fakeip_admin"
	"go.uber.org/zap"
)

// MappingEntry and MappingStats are aliases of the shared admin types, so
// callers can use either the concrete plugin or pkg/fakeip_admin.
type (
	MappingEntry = fakeipadmin.Entry
	MappingStats = fakeipadmin.Stats
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

// AdminClearMappings drops every mapping. It is meant for a deliberate reset:
// in-flight DNS answers keep working until the client re-resolves.
func (p *FakeIPNatPlugin) AdminClearMappings(ctx context.Context) (int64, error) {
	res, err := p.db.ExecContext(ctx, `DELETE FROM `+p.mapTable)
	if err != nil {
		return 0, fmt.Errorf("clear mappings: %w", err)
	}
	n, _ := res.RowsAffected()

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
