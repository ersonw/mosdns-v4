package fakeipnat

import (
	"context"
	"fmt"
	"strings"
	"time"

	"go.uber.org/zap"
)

// defaultRecordTTL is how long a mapping survives without being queried: seven
// days. Both tables are swept: the domain <-> fake ip mapping and the real ips
// remembered for it.
const defaultRecordTTL = 7 * 24 * time.Hour

// retentionMinInterval keeps a very small record_ttl from turning the sweep into
// a busy loop; the config is accepted, only its frequency is bounded.
const retentionMinInterval = time.Minute

// parseRecordTTL decodes record_ttl. An empty value keeps the default, and "0"
// disables the sweep entirely (records then live as long as the database file).
func parseRecordTTL(raw string) (time.Duration, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return defaultRecordTTL, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("invalid record_ttl %q: %w", raw, err)
	}
	if d < 0 {
		return 0, fmt.Errorf("invalid record_ttl %q: must not be negative", raw)
	}
	return d, nil
}

// startRecordRetention launches the background sweep. It is a no-op when the
// retention is disabled.
func (p *FakeIPNatPlugin) startRecordRetention() {
	if p.recordTTL <= 0 {
		p.L().Info("fakeip nat: record retention disabled", zap.String("record_ttl", "0"))
		return
	}
	stop := make(chan struct{})
	p.retentionStop = stop
	go p.recordRetentionLoop(stop)
	p.L().Info("fakeip nat: record retention started",
		zap.Duration("record_ttl", p.recordTTL), zap.Duration("interval", p.retentionInterval()))
}

// stopRecordRetention closes the stop channel exactly once. The loop gets the
// channel as an argument instead of re-reading the field, otherwise Close racing
// the loop is a data race.
func (p *FakeIPNatPlugin) stopRecordRetention() {
	p.retentionOnce.Do(func() {
		if p.retentionStop != nil {
			close(p.retentionStop)
		}
	})
}

func (p *FakeIPNatPlugin) retentionInterval() time.Duration {
	interval := p.recordTTL
	if interval > time.Hour {
		interval = time.Hour
	}
	if interval < retentionMinInterval {
		interval = retentionMinInterval
	}
	return interval
}

func (p *FakeIPNatPlugin) recordRetentionLoop(stop <-chan struct{}) {
	// The first pass runs shortly after startup so a long downtime is cleaned
	// up right away, without blocking Init on a large table.
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	ticker := time.NewTicker(p.retentionInterval())
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			return
		case <-timer.C:
			p.sweepRecords(context.Background())
		case <-ticker.C:
			p.sweepRecords(context.Background())
		}
	}
}

// sweepRecords drops mappings and real ips that have not been used within
// record_ttl, then hands the freed fake ips back to the allocator. The last-seen
// value is the newest of: the in-memory touch, the stored last_seen and
// created_at, so a database restored from an old backup is not wiped wholesale
// just because its last_seen column is empty.
func (p *FakeIPNatPlugin) sweepRecords(ctx context.Context) {
	if p.recordTTL <= 0 {
		return
	}
	cutoff := time.Now().Add(-p.recordTTL).Unix()

	// Serialize with the allocator: the sweep reads the runtime table and the
	// database together, and a concurrent allocation would make both views
	// disagree.
	p.mu.Lock()
	defer p.mu.Unlock()

	type mappingRow struct {
		domain string
		fakeIP string
		stored int64
		newest int64
	}
	rows, err := p.db.QueryContext(ctx, fmt.Sprintf(
		"SELECT domain, fake_ip, COALESCE(created_at,0), COALESCE(last_seen,0) FROM %s", p.mapTable))
	if err != nil {
		p.L().Warn("fakeip nat: retention scan failed", zap.Error(err))
		return
	}
	var all []mappingRow
	for rows.Next() {
		var r mappingRow
		if err := rows.Scan(&r.domain, &r.fakeIP, &r.stored, &r.newest); err != nil {
			rows.Close()
			p.L().Warn("fakeip nat: retention scan failed", zap.Error(err))
			return
		}
		if mem := p.runtime.lastSeenOf(r.domain); mem > r.newest {
			r.newest = mem
		}
		if r.stored > r.newest {
			r.newest = r.stored
		}
		all = append(all, r)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		p.L().Warn("fakeip nat: retention scan failed", zap.Error(err))
		return
	}
	rows.Close()

	var expired, refreshed []mappingRow
	for _, r := range all {
		if r.fakeIP == pendingFakeIP {
			continue // an allocation in progress is never expired
		}
		if r.newest < cutoff {
			expired = append(expired, r)
			continue
		}
		if r.newest > r.stored {
			refreshed = append(refreshed, r)
		}
	}

	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		p.L().Warn("fakeip nat: retention transaction failed", zap.Error(err))
		return
	}
	removed := 0
	for _, r := range expired {
		if _, err := tx.ExecContext(ctx,
			fmt.Sprintf("DELETE FROM %s WHERE domain = ? AND fake_ip = ?", p.mapTable), r.domain, r.fakeIP); err != nil {
			_ = tx.Rollback()
			p.L().Warn("fakeip nat: retention delete failed", zap.String("domain", r.domain), zap.Error(err))
			return
		}
		removed++
	}
	for _, r := range refreshed {
		if _, err := tx.ExecContext(ctx,
			fmt.Sprintf("UPDATE %s SET last_seen = ? WHERE domain = ?", p.mapTable), r.newest, r.domain); err != nil {
			_ = tx.Rollback()
			p.L().Warn("fakeip nat: retention update failed", zap.String("domain", r.domain), zap.Error(err))
			return
		}
	}
	// The real ip table is pure history behind the mapping; drop its stale rows
	// in the same transaction.
	res, err := tx.ExecContext(ctx,
		fmt.Sprintf("DELETE FROM %s WHERE last_seen < ?", p.ipTable), cutoff)
	if err != nil {
		_ = tx.Rollback()
		p.L().Warn("fakeip nat: retention real ip sweep failed", zap.Error(err))
		return
	}
	realRemoved, _ := res.RowsAffected()
	if err := tx.Commit(); err != nil {
		p.L().Warn("fakeip nat: retention commit failed", zap.Error(err))
		return
	}

	// Only now release the addresses: the rows are gone, so the allocator may
	// hand the same fake ip to the next domain.
	for _, r := range expired {
		p.runtime.remove(r.domain)
	}
	p.L().Debug("fakeip nat: retention sweep done",
		zap.Int("scanned", len(all)), zap.Int("expired", removed),
		zap.Int("refreshed", len(refreshed)), zap.Int64("real_ips_dropped", realRemoved),
		zap.Int64("cutoff", cutoff))
}
