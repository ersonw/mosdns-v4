package fakeipnat

// The mark path and the tun SNAT table belong to the run that installed them,
// and Close removes them again. A crash, a SIGKILL or a configuration change in
// between leaves them behind, and the next run cannot recognise them from its
// own configuration: route_mark may have been deleted, the proxy may be
// configured now, the table number may differ. The state recorded here is what
// makes that cleanup exact instead of guessed - the previous run says which
// mark and which table it installed, so the next one can remove precisely that
// and nothing else (VyOS and gost keep their own fwmarks in the same ruleset).

import (
	"context"
	"strconv"

	"go.uber.org/zap"
)

const (
	stateKeyMark  = "route_mark"
	stateKeyTable = "route_table"
)

// loadMarkState returns the mark path the previous run installed. A zero mark
// or an unusable table (empty, main) means "nothing recorded": there is nothing
// safe to clean up.
func (p *FakeIPNatPlugin) loadMarkState(ctx context.Context) (uint32, string) {
	if p.db == nil || p.stateTable == "" {
		return 0, ""
	}
	rows, err := p.db.QueryContext(ctx,
		"SELECT key, value FROM "+p.stateTable+" WHERE key IN ('"+stateKeyMark+"','"+stateKeyTable+"')")
	if err != nil {
		p.L().Debug("route mark: reading the recorded state failed", zap.Error(err))
		return 0, ""
	}
	defer rows.Close()

	var markValue, tableValue string
	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			p.L().Debug("route mark: reading the recorded state failed", zap.Error(err))
			return 0, ""
		}
		switch key {
		case stateKeyMark:
			markValue = value
		case stateKeyTable:
			tableValue = value
		}
	}
	if err := rows.Err(); err != nil {
		p.L().Debug("route mark: reading the recorded state failed", zap.Error(err))
		return 0, ""
	}

	mark, perr := strconv.ParseUint(markValue, 10, 32)
	if perr != nil || mark == 0 || tableValue == "" || tableValue == "main" {
		return 0, ""
	}
	return uint32(mark), tableValue
}

// saveMarkState records the path just installed, so a later run can undo it.
func (p *FakeIPNatPlugin) saveMarkState(ctx context.Context, mark uint32, table string) {
	if p.db == nil || p.stateTable == "" {
		return
	}
	statement := "INSERT OR REPLACE INTO " + p.stateTable + " (key, value) VALUES (?, ?), (?, ?)"
	if _, err := p.db.ExecContext(ctx, statement,
		stateKeyMark, strconv.FormatUint(uint64(mark), 10), stateKeyTable, table); err != nil {
		p.L().Warn("route mark: recording the installed path failed", zap.Error(err))
	}
}

// clearMarkState forgets the recorded path once it has been removed.
func (p *FakeIPNatPlugin) clearMarkState(ctx context.Context) {
	if p.db == nil || p.stateTable == "" {
		return
	}
	if _, err := p.db.ExecContext(ctx,
		"DELETE FROM "+p.stateTable+" WHERE key IN ('"+stateKeyMark+"','"+stateKeyTable+"')"); err != nil {
		p.L().Debug("route mark: clearing the recorded state failed", zap.Error(err))
	}
}

// removeStaleMarkPath deletes the policy rule and the default route a previous
// run installed. The rule is matched by fwmark and table only: its priority may
// have changed since, and a rule that is not there is the normal case.
func (p *FakeIPNatPlugin) removeStaleMarkPath(ctx context.Context, mark uint32, table string) {
	if mark == 0 || table == "" || table == "main" {
		return
	}
	markText := strconv.FormatUint(uint64(mark), 10)
	if _, err := p.runner.Run(ctx, "ip", "rule", "del", "fwmark", markText, "lookup", table); err == nil {
		p.L().Info("route mark: removed the policy rule a previous run installed",
			zap.Uint32("mark", mark), zap.String("route_table", table))
	} else {
		p.L().Debug("route mark: no policy rule to remove",
			zap.Uint32("mark", mark), zap.String("route_table", table))
	}
	if _, err := p.runner.Run(ctx, "ip", "route", "del", "default", "table", table); err == nil {
		p.L().Info("route mark: removed the default route a previous run installed", zap.String("route_table", table))
	} else {
		p.L().Debug("route mark: no default route to remove", zap.String("route_table", table))
	}
}

// removeStaleTunSNAT drops the outlet's SNAT table when the configured outlet is
// a proxy: that table is only installed without one, and a proxied start never
// reaches setupTunEgress' install path, so nothing else would ever remove it.
func (p *FakeIPNatPlugin) removeStaleTunSNAT(ctx context.Context) {
	table := p.tunSNATTableName()
	if _, err := p.runner.Run(ctx, "nft", "delete", "table", "ip", table); err == nil {
		p.L().Info("tun egress: removed the snat table a proxied run does not use", zap.String("nft_table", table))
	} else {
		p.L().Debug("tun egress: no snat table to remove", zap.String("nft_table", table))
	}
}
