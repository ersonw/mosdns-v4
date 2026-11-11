//go:build linux

package fakeipnat

// The linux outlet needs the masquerade: its sockets are bound to the range
// address on purpose, and only a postrouting rewrite turns that source back
// into an address the upstream gateway can answer.

import (
	"context"
	"strings"

	"go.uber.org/zap"
)

func (p *FakeIPNatPlugin) installTunSNAT(ctx context.Context) (func(), bool) {
	if p.proxyActive {
		p.L().Debug("tun snat: proxy carries the outlet, no host rewrite needed")
		return nil, false
	}
	table := p.tunSNATTableName()
	plan := tunSNATPlan(table, p.tunEgressDev, p.cidr)
	if len(plan) == 0 {
		p.L().Warn("tun snat: no egress device known, masquerade not installed",
			zap.String("range", p.cidr))
		return nil, false
	}

	// The first command is a best-effort delete of a leftover table.
	if _, err := p.runner.Run(ctx, "nft", plan[0]...); err != nil {
		p.L().Debug("tun snat: no stale table to delete",
			zap.String("nft_table", table), zap.String("stderr", err.Error()))
	}
	for _, args := range plan[1:] {
		if _, err := p.runner.Run(ctx, "nft", args...); err != nil {
			p.L().Warn("tun snat: masquerade install failed",
				zap.String("nft_table", table), zap.String("cmd", strings.Join(args, " ")), zap.Error(err))
			return nil, false
		}
	}

	p.L().Info("tun snat: masquerade installed",
		zap.String("nft_table", table), zap.String("dev", p.tunEgressDev),
		zap.String("range", p.cidr), zap.String("next_hop", p.tunEgressHop))

	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
		defer cancel()
		if _, err := p.runner.Run(ctx, "nft", "delete", "table", "ip", table); err != nil {
			p.L().Debug("tun snat: remove masquerade failed", zap.String("nft_table", table), zap.Error(err))
			return
		}
		p.L().Debug("tun snat: masquerade removed", zap.String("nft_table", table))
	}, true
}
