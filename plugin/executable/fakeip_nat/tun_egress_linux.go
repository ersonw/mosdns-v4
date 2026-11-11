//go:build linux

package fakeipnat

// This file installs the linux side of the tun outlet: one default route in a
// dedicated table, plus an ip rule that sends every packet sourced from the
// fake range into it. Both commands are idempotent (replace, delete then add).

import (
	"context"

	"go.uber.org/zap"
)

func (p *FakeIPNatPlugin) installTunEgressRoute(ctx context.Context) (func(), bool) {
	table := p.tunRouteTable
	if table == "" {
		table = "main"
	}
	plan := tunRoutePlan(p.cidr, p.tunEgressHop, p.tunEgressDev, table)
	if len(plan) == 0 {
		p.L().Warn("tun egress: neither gateway nor device is known, route table not installed")
		return nil, false
	}

	if _, err := p.runner.Run(ctx, plan[0][0], plan[0][1:]...); err != nil {
		p.L().Warn("tun egress: install default route failed",
			zap.String("table", table), zap.String("next_hop", p.tunEgressHop),
			zap.String("dev", p.tunEgressDev), zap.Error(err))
		return nil, false
	}

	// A previous run may have left the rule behind; the delete is best effort.
	_, _ = p.runner.Run(ctx, plan[1][0], plan[1][1:]...)
	if _, err := p.runner.Run(ctx, plan[2][0], plan[2][1:]...); err != nil {
		p.L().Warn("tun egress: add ip rule failed",
			zap.String("from", p.cidr), zap.String("table", table), zap.Error(err))
		_, _ = p.runner.Run(ctx, "ip", "route", "del", "default", "table", table)
		return nil, false
	}

	p.L().Info("tun egress: routing table installed",
		zap.String("table", table), zap.String("next_hop", p.tunEgressHop),
		zap.String("dev", p.tunEgressDev), zap.String("from", p.cidr))

	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
		defer cancel()
		_, _ = p.runner.Run(ctx, "ip", "rule", "del", "from", p.cidr, "lookup", table)
		_, _ = p.runner.Run(ctx, "ip", "route", "del", "default", "table", table)
		p.L().Debug("tun egress: routing table removed", zap.String("table", table), zap.String("from", p.cidr))
	}, true
}
