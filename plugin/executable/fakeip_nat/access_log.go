package fakeipnat

// Per-client access log. The plugin already knows which domain is mapped to
// which fake ip; what it did not record is WHO asked. This table keeps one row
// per (client ip, domain) pair, so an administrator can later ask "what did
// the machine behind this address resolve" without shell access to the box.
//
// The row is written on the answer path but never blocks it: a failure is
// logged and the query is answered as before. real_ip is not stored here; it is
// joined from the existing real ip table at read time, so a later learned
// address is visible without rewriting history.

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/ersonw/mosdns-v4/pkg/fakeip_admin"
	"github.com/ersonw/mosdns-v4/pkg/query_context"
	"go.uber.org/zap"
)

// defaultAccessTTL is how long one access row survives without being seen
// again. It matches the mapping default so both tables age out together.
const defaultAccessTTL = 7 * 24 * time.Hour

// parseAccessTTL decodes access_ttl. Empty keeps the default, "0" disables the
// automatic sweep, and a negative value is rejected.
func parseAccessTTL(raw string) (time.Duration, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return defaultAccessTTL, nil
	}
	if raw == "0" {
		return 0, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("invalid access_ttl %q: %w", raw, err)
	}
	if d < 0 {
		return 0, fmt.Errorf("invalid access_ttl %q: must not be negative", raw)
	}
	return d, nil
}

func accessTableSQL(accessTable string) string {
	return fmt.Sprintf(`
	CREATE TABLE IF NOT EXISTS %s (
		client_ip TEXT NOT NULL,
		domain TEXT NOT NULL,
		fake_ip TEXT NOT NULL DEFAULT '',
		first_seen INTEGER DEFAULT 0,
		last_seen INTEGER DEFAULT 0,
		hits INTEGER DEFAULT 0,
		PRIMARY KEY (client_ip, domain)
	);
	CREATE INDEX IF NOT EXISTS idx_%s_last_seen ON %s(last_seen);`, accessTable, accessTable, accessTable)
}

// recordAccess notes that clientIP resolved domain to fakeIP. It is
// deliberately best effort: the answer has already been produced and must not
// be delayed or failed by bookkeeping.
func (p *FakeIPNatPlugin) recordAccess(qCtx *query_context.Context, domain, fakeIP string) {
	if !p.accessLog {
		return
	}
	meta := qCtx.ReqMeta()
	if meta == nil || !meta.ClientAddr.IsValid() {
		// A query that came from a pipe or a test harness has no source address;
		// without one the row would be unattributable.
		return
	}
	clientIP := meta.ClientAddr.Unmap().String()
	now := time.Now().Unix()

	// The upsert keeps first_seen and increments hits, so one client hitting
	// the same domain repeatedly stays one row.
	stmt := fmt.Sprintf(`INSERT INTO %s (client_ip, domain, fake_ip, first_seen, last_seen, hits)
		VALUES (?, ?, ?, ?, ?, 1)
		ON CONFLICT(client_ip, domain) DO UPDATE SET
			fake_ip = excluded.fake_ip,
			last_seen = excluded.last_seen,
			hits = hits + 1`, p.accessTable)
	if _, err := p.db.ExecContext(context.Background(), stmt, clientIP, domain, fakeIP, now, now); err != nil {
		p.L().Warn("fakeip nat: access record failed",
			zap.String("client_ip", clientIP), zap.String("domain", domain), zap.Error(err))
		return
	}
	p.L().Debug("fakeip nat: access recorded",
		zap.String("client_ip", clientIP), zap.String("domain", domain), zap.String("fake_ip", fakeIP))
}

// sweepAccess drops access rows nobody has hit within access_ttl. It runs from
// the same loop as the mapping sweep, so both tables age out on one schedule.
func (p *FakeIPNatPlugin) sweepAccess(ctx context.Context) {
	if !p.accessLog || p.accessTTL <= 0 {
		return
	}
	cutoff := time.Now().Add(-p.accessTTL).Unix()
	res, err := p.db.ExecContext(ctx, fmt.Sprintf("DELETE FROM %s WHERE last_seen < ?", p.accessTable), cutoff)
	if err != nil {
		p.L().Warn("fakeip nat: access sweep failed", zap.Error(err))
		return
	}
	if n, _ := res.RowsAffected(); n > 0 {
		p.L().Info("fakeip nat: access records dropped", zap.Int64("dropped", n))
	}
}

// AdminAccessRecords implements the read side used by the control surface: the
// rows of the given client addresses, newest first, with the real ip learned
// for the domain joined in.
func (p *FakeIPNatPlugin) AdminAccessRecords(ctx context.Context, clientIPs []string, since int64, limit int) ([]fakeipadmin.AccessRecord, error) {
	if len(clientIPs) == 0 {
		return nil, nil
	}
	if limit <= 0 || limit > 5000 {
		limit = 2000
	}

	placeholders := make([]string, len(clientIPs))
	args := make([]interface{}, 0, len(clientIPs)+1)
	for i, ip := range clientIPs {
		placeholders[i] = "?"
		args = append(args, ip)
	}
	if since > 0 {
		args = append(args, since)
	}

	query := fmt.Sprintf(`SELECT a.client_ip, a.domain, a.fake_ip, a.first_seen, a.last_seen, a.hits,
			COALESCE((SELECT r.real_ip FROM %s r WHERE r.domain = a.domain ORDER BY r.last_seen DESC LIMIT 1), '')
		FROM %s a
		WHERE a.client_ip IN (%s)`, p.ipTable, p.accessTable, strings.Join(placeholders, ","))
	if since > 0 {
		query += " AND a.last_seen >= ?"
	}
	query += " ORDER BY a.last_seen DESC LIMIT ?"
	args = append(args, limit)

	rows, err := p.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query access records: %w", err)
	}
	defer rows.Close()

	records := make([]fakeipadmin.AccessRecord, 0, limit)
	for rows.Next() {
		var r fakeipadmin.AccessRecord
		if err := rows.Scan(&r.ClientIP, &r.Domain, &r.FakeIP, &r.FirstSeen, &r.LastSeen, &r.Hits, &r.RealIP); err != nil {
			return nil, fmt.Errorf("scan access record: %w", err)
		}
		records = append(records, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read access records: %w", err)
	}
	return records, nil
}

// ensureAccessTable creates the access table for a database that predates it.
func ensureAccessTable(db *sql.DB, accessTable string) error {
	if _, err := db.Exec(accessTableSQL(accessTable)); err != nil {
		return fmt.Errorf("init access table: %w", err)
	}
	return nil
}
