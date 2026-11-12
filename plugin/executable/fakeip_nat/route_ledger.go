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
	"net/netip"
	"sync"
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

// routeLedger holds the rows in memory and writes them behind. A route is
// installed while an answer is being produced, so a SQLite round trip per
// prefix is paid on every answer; the rows are flushed by the maintenance loop
// and once more before the plugin removes its routes.
//
// The memory copy is also what the cleanup reads: once loaded, no step of the
// data path or of the sweep has to ask SQLite again.
type routeLedger struct {
	mu      sync.Mutex
	rows    map[string]ledgerRoute // prefix -> row as installed
	dirty   map[string]bool        // prefixes written since the last flush
	removed map[string]bool        // prefixes forgotten since the last flush
	loaded  bool
}

func newRouteLedger() *routeLedger {
	return &routeLedger{
		rows:    make(map[string]ledgerRoute),
		dirty:   make(map[string]bool),
		removed: make(map[string]bool),
	}
}

func (l *routeLedger) remember(r ledgerRoute) {
	if r.prefix == "" {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.rows[r.prefix] = r
	l.dirty[r.prefix] = true
	delete(l.removed, r.prefix)
}

func (l *routeLedger) forget(prefix string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.rows[prefix]; ok {
		delete(l.rows, prefix)
	}
	delete(l.dirty, prefix)
	l.removed[prefix] = true
}

func (l *routeLedger) replace(rows []ledgerRoute) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.rows = make(map[string]ledgerRoute, len(rows))
	for _, r := range rows {
		l.rows[r.prefix] = r
	}
	l.dirty = make(map[string]bool)
	l.removed = make(map[string]bool)
	l.loaded = true
}

// mergeLoaded adds the rows read from SQLite without dropping anything the
// data path already recorded since startup.
func (l *routeLedger) mergeLoaded(rows []ledgerRoute) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, r := range rows {
		if _, ok := l.rows[r.prefix]; ok {
			continue
		}
		l.rows[r.prefix] = r
	}
	l.loaded = true
}

func (l *routeLedger) snapshot() []ledgerRoute {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]ledgerRoute, 0, len(l.rows))
	for _, r := range l.rows {
		out = append(out, r)
	}
	return out
}

func (l *routeLedger) size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.rows)
}

func (l *routeLedger) isLoaded() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.loaded
}

// takePending hands the writes and deletions since the last flush to the
// caller, so a failed transaction can put them back with restore.
func (l *routeLedger) takePending() ([]ledgerRoute, []string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.dirty) == 0 && len(l.removed) == 0 {
		return nil, nil
	}
	upserts := make([]ledgerRoute, 0, len(l.dirty))
	for prefix := range l.dirty {
		if r, ok := l.rows[prefix]; ok {
			upserts = append(upserts, r)
		}
	}
	deletes := make([]string, 0, len(l.removed))
	for prefix := range l.removed {
		deletes = append(deletes, prefix)
	}
	l.dirty = make(map[string]bool)
	l.removed = make(map[string]bool)
	return upserts, deletes
}

func (l *routeLedger) restorePending(upserts []ledgerRoute, deletes []string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, r := range upserts {
		l.dirty[r.prefix] = true
	}
	for _, prefix := range deletes {
		l.removed[prefix] = true
	}
}

func (l *routeLedger) reset() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.rows = make(map[string]ledgerRoute)
	l.dirty = make(map[string]bool)
	l.removed = make(map[string]bool)
}

// rememberManagedRoute records a prefix that was just installed. It only
// touches memory: the answer path must not wait on the database.
func (p *FakeIPNatPlugin) rememberManagedRoute(ctx context.Context, prefix, hop, dev string) {
	if p.routesTable == "" {
		return
	}
	if p.ledger == nil {
		p.ledger = newRouteLedger()
	}
	p.ledger.remember(ledgerRoute{prefix: prefix, nextHop: hop, dev: dev, routeTable: p.hostRouteTable()})
}

// forgetManagedRoute drops a prefix from the ledger once it no longer exists in
// the routing table.
func (p *FakeIPNatPlugin) forgetManagedRoute(ctx context.Context, prefix string) {
	if p.routesTable == "" || p.ledger == nil {
		return
	}
	p.ledger.forget(prefix)
}

// loadLedger fills the memory copy once, at startup. A failure is not fatal:
// the plugin keeps running with whatever it could read.
func (p *FakeIPNatPlugin) loadLedger(ctx context.Context) error {
	if p.routesTable == "" {
		p.ledger = newRouteLedger()
		return nil
	}
	if p.ledger == nil {
		p.ledger = newRouteLedger()
	}
	routes, err := p.readLedger(ctx)
	if err != nil {
		return err
	}
	p.ledger.replace(routes)
	p.L().Debug("fakeip nat: route ledger loaded into memory", zap.Int("rows", len(routes)))
	return nil
}

// ledgerRoutes returns every recorded prefix with the values it was installed
// with. Once loaded this is a memory read; SQLite is only asked when nothing
// has been loaded yet (a unit test, or a plugin built without Init).
func (p *FakeIPNatPlugin) ledgerRoutes(ctx context.Context) ([]ledgerRoute, error) {
	if p.routesTable == "" {
		return nil, nil
	}
	if p.ledger == nil {
		p.ledger = newRouteLedger()
	}
	if !p.ledger.isLoaded() {
		// Rows written before the load are not lost: the database fills the gaps
		// and anything already in memory wins.
		routes, err := p.readLedger(ctx)
		if err != nil {
			return nil, err
		}
		p.ledger.mergeLoaded(routes)
	}
	return p.ledger.snapshot(), nil
}

func (p *FakeIPNatPlugin) readLedger(ctx context.Context) ([]ledgerRoute, error) {
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

// flushLedger writes the pending rows and deletions in one transaction. Called
// from the maintenance loop and on shutdown; a failure puts them back so the
// next tick retries instead of silently dropping the record.
func (p *FakeIPNatPlugin) flushLedger(ctx context.Context) {
	if p.routesTable == "" || p.ledger == nil {
		return
	}
	upserts, deletes := p.ledger.takePending()
	if len(upserts) == 0 && len(deletes) == 0 {
		return
	}
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		p.ledger.restorePending(upserts, deletes)
		p.L().Warn("fakeip nat: flush route ledger failed", zap.Error(err))
		return
	}
	for _, prefix := range deletes {
		if _, err := tx.ExecContext(ctx, fmt.Sprintf("DELETE FROM %s WHERE prefix = ?", p.routesTable), prefix); err != nil {
			_ = tx.Rollback()
			p.ledger.restorePending(upserts, deletes)
			p.L().Warn("fakeip nat: flush route ledger failed", zap.Error(err))
			return
		}
	}
	for _, r := range upserts {
		if _, err := tx.ExecContext(ctx,
			fmt.Sprintf("INSERT INTO %s (prefix, next_hop, dev, route_table, created_at) VALUES (?, ?, ?, ?, ?) "+
				"ON CONFLICT(prefix) DO UPDATE SET next_hop = excluded.next_hop, dev = excluded.dev, route_table = excluded.route_table",
				p.routesTable),
			r.prefix, r.nextHop, r.dev, r.routeTable, time.Now().Unix()); err != nil {
			_ = tx.Rollback()
			p.ledger.restorePending(upserts, deletes)
			p.L().Warn("fakeip nat: flush route ledger failed", zap.Error(err))
			return
		}
	}
	if err := tx.Commit(); err != nil {
		p.ledger.restorePending(upserts, deletes)
		p.L().Warn("fakeip nat: flush route ledger failed", zap.Error(err))
		return
	}
	p.L().Debug("fakeip nat: route ledger flushed", zap.Int("upserts", len(upserts)), zap.Int("deletes", len(deletes)))
}

// clearLedger empties the record after its prefixes were removed.
func (p *FakeIPNatPlugin) clearLedger(ctx context.Context) {
	if p.routesTable == "" {
		return
	}
	if p.ledger != nil {
		p.ledger.reset()
	}
	if _, err := p.db.ExecContext(ctx, fmt.Sprintf("DELETE FROM %s", p.routesTable)); err != nil {
		p.L().Warn("fakeip nat: clear route ledger failed", zap.Error(err))
	}
}

// startMaintenance runs the loop that keeps the durable copies fresh without
// putting any of that work on the answer path: the route ledger is flushed and
// the system default route is re-resolved for the next data path use.
func (p *FakeIPNatPlugin) startMaintenance() {
	if p.useTun {
		return
	}
	p.maintMu.Lock()
	if p.maintStop != nil {
		p.maintMu.Unlock()
		return
	}
	stop := make(chan struct{})
	done := make(chan struct{})
	p.maintStop, p.maintDone = stop, done
	p.maintMu.Unlock()

	go func() {
		defer close(done)
		ticker := time.NewTicker(routeAggInterval)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				p.flushLedger(context.Background())
				return
			case <-ticker.C:
				p.flushLedger(context.Background())
				p.refreshFallbackHopDev()
			}
		}
	}()
	p.L().Debug("fakeip nat: maintenance loop started",
		zap.Duration("interval", routeAggInterval), zap.Int("ledger_rows", p.ledgerSize()))
}

func (p *FakeIPNatPlugin) stopMaintenance() {
	p.maintMu.Lock()
	stop, done := p.maintStop, p.maintDone
	p.maintStop, p.maintDone = nil, nil
	p.maintMu.Unlock()
	if stop == nil {
		return
	}
	close(stop)
	<-done
}

func (p *FakeIPNatPlugin) ledgerSize() int {
	if p.ledger == nil {
		return 0
	}
	return p.ledger.size()
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
//
// ledgerOwnsPrefix reports whether a route in the kernel came from this plugin:
// it is either a ledger row verbatim, or exactly the aggregate an earlier
// collapse pass installed (the union of rows that still point at the same hop).
// Anything else is the operator's own route and must be left alone.
func (p *FakeIPNatPlugin) ledgerOwnsPrefix(prefix string) bool {
	p.ledgerMu.Lock()
	ledger := p.ledger
	p.ledgerMu.Unlock()
	if ledger == nil {
		return false
	}
	rows := ledger.snapshot()
	if len(rows) == 0 {
		return false
	}
	prefixes := make([]netip.Prefix, 0, len(rows))
	for _, row := range rows {
		if row.prefix == prefix {
			return true
		}
		if pfx, err := netip.ParsePrefix(row.prefix); err == nil {
			prefixes = append(prefixes, pfx)
		}
	}
	for _, pfx := range collapsePrefixes(prefixes) {
		if pfx.String() == prefix {
			return true
		}
	}
	return false
}

// foreignRoute reports whether a scanned prefix has no record in the ledger,
// which means the scan found somebody else's route that merely looks like ours.
func (p *FakeIPNatPlugin) foreignRoute(prefix string) bool {
	if p.ledgerSize() == 0 {
		// Nothing recorded - an older binary or an empty database - so the
		// scan is the only trail there is.
		return false
	}
	return !p.ledgerOwnsPrefix(prefix)
}

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
		if p.foreignRoute(prefix) {
			p.L().Debug("fakeip nat: residual scan left a route the ledger does not own",
				zap.String("prefix", prefix), zap.String("next_hop", hop), zap.String("dev", dev))
			continue
		}
		routesDeleted += p.deleteManagedRoutes(ctx, []string{prefix})
	}
	p.L().Info("fakeip nat: residual routes swept at startup",
		zap.Int("ledger_deleted", ledgerDeleted), zap.Int("scanned", scanned),
		zap.Int("routes_deleted", routesDeleted), zap.Int("known_real_ips", len(known)),
		zap.String("next_hop", hop), zap.String("dev", dev))
}
