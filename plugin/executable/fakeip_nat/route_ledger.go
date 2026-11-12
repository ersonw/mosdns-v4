package fakeipnat

// The route ledger keeps every prefix this plugin installed, so a stop, a
// crash, a reload or a configuration change cannot leave a host route behind
// that nothing will ever remove. The routing table itself cannot be asked
// "which of these are yours": a scan by gateway/device also matches routes the
// operator configured by hand, and a scan after a crash has no way to tell how
// many of the leftovers belong to this plugin.
//
// The ledger records the prefix together with the hop, device and table that
// were in effect when it was written, so a deletion uses the same values even
// if the configuration has changed since.

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"
)

// ledgerRoute is one row of the managed route table.
type ledgerRoute struct {
	prefix     string
	nextHop    string
	dev        string
	routeTable string
}

// rememberManagedRoute records a prefix that was just installed. The write is
// best effort: losing the row leaves one route behind, which is strictly better
// than failing the data path.
func (p *FakeIPNatPlugin) rememberManagedRoute(ctx context.Context, prefix, hop, dev string) {
	if p.routesTable == "" {
		return
	}
	_, err := p.db.ExecContext(ctx,
		fmt.Sprintf("INSERT INTO %s (prefix, next_hop, dev, route_table, created_at) VALUES (?, ?, ?, ?, ?) "+
			"ON CONFLICT(prefix) DO UPDATE SET next_hop = excluded.next_hop, dev = excluded.dev, route_table = excluded.route_table",
			p.routesTable),
		prefix, hop, dev, p.hostRouteTable(), time.Now().Unix())
	if err != nil {
		p.L().Warn("fakeip nat: record managed route failed",
			zap.String("prefix", prefix), zap.String("route_table", p.hostRouteTable()), zap.Error(err))
	}
}

// forgetManagedRoute drops a prefix from the ledger once it no longer exists in
// the routing table.
func (p *FakeIPNatPlugin) forgetManagedRoute(ctx context.Context, prefix string) {
	if p.routesTable == "" {
		return
	}
	if _, err := p.db.ExecContext(ctx, fmt.Sprintf("DELETE FROM %s WHERE prefix = ?", p.routesTable), prefix); err != nil {
		p.L().Debug("fakeip nat: forget managed route failed",
			zap.String("prefix", prefix), zap.Error(err))
	}
}

// ledgerRoutes reads every recorded prefix with the values it was installed
// with.
func (p *FakeIPNatPlugin) ledgerRoutes(ctx context.Context) ([]ledgerRoute, error) {
	if p.routesTable == "" {
		return nil, nil
	}
	rows, err := p.db.QueryContext(ctx,
		fmt.Sprintf("SELECT prefix, next_hop, dev, route_table FROM %s", p.routesTable))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []ledgerRoute
	for rows.Next() {
		var r ledgerRoute
		if err := rows.Scan(&r.prefix, &r.nextHop, &r.dev, &r.routeTable); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// clearLedger empties the record after its prefixes were removed.
func (p *FakeIPNatPlugin) clearLedger(ctx context.Context) {
	if p.routesTable == "" {
		return
	}
	if _, err := p.db.ExecContext(ctx, fmt.Sprintf("DELETE FROM %s", p.routesTable)); err != nil {
		p.L().Warn("fakeip nat: clear route ledger failed", zap.Error(err))
	}
}

// sweepLedgerRoutes deletes every prefix the ledger names, using the route table
// each row was written with, and then clears the record. It is the exact
// counterpart of the writes: no scan, no filter, no guess.
func (p *FakeIPNatPlugin) sweepLedgerRoutes(ctx context.Context) int {
	routes, err := p.ledgerRoutes(ctx)
	if err != nil {
		p.L().Warn("fakeip nat: read route ledger failed", zap.Error(err))
		return 0
	}
	if len(routes) == 0 {
		return 0
	}

	deleted := 0
	for _, r := range routes {
		commands := routeDeleteCommands(r.prefix, r.routeTable)
		for _, cmd := range commands {
			if _, err := p.runner.Run(ctx, cmd[0], cmd[1:]...); err == nil {
				deleted++
			}
		}
	}
	// The record is cleared either way: a prefix that is already gone reports an
	// error on delete, and keeping it would replay the same failure forever.
	p.clearLedger(ctx)
	p.L().Info("fakeip nat: recorded routes removed",
		zap.Int("recorded", len(routes)), zap.Int("commands_ok", deleted))
	return deleted
}

// sweepResidualRoutes removes what an earlier process left behind. Two passes,
// in order of confidence:
//
//  1. the ledger: exact prefixes this plugin wrote, deleted with the values they
//     were written with;
//  2. a scan of the routing table for routes that still point at the configured
//     gateway/device and cover an address this plugin is responsible for. This
//     catches the routes written by a build that had no ledger.
func (p *FakeIPNatPlugin) sweepResidualRoutes() {
	ctx, cancel := context.WithTimeout(context.Background(), natTimeout)
	defer cancel()

	ledgerDeleted := p.sweepLedgerRoutes(ctx)
	if p.useTun {
		// The tun data path writes one route for the whole range and removes it
		// with the device, so there is nothing to scan for.
		return
	}

	hop, dev := p.nextHop, p.nextHopDev
	if hop == "" && dev == "" {
		hop, dev = p.systemDefaultRoute(ctx)
	}
	if hop == "" && dev == "" {
		p.L().Debug("fakeip nat: residual route scan skipped, no next hop and no device")
		return
	}

	known := p.knownRealIPs(ctx)
	scanned := 0
	routesDeleted := 0
	for _, prefix := range p.listManagedRoutes(ctx, hop, dev) {
		scanned++
		if !manageablePrefix(prefix) || !prefixCoversAny(prefix, known) {
			continue
		}
		routesDeleted += p.deleteManagedRoutes(ctx, []string{prefix})
	}
	p.L().Info("fakeip nat: residual routes swept at startup",
		zap.Int("ledger_deleted", ledgerDeleted), zap.Int("scanned", scanned),
		zap.Int("routes_deleted", routesDeleted), zap.Int("known_real_ips", len(known)),
		zap.String("next_hop", hop), zap.String("dev", dev))
}
