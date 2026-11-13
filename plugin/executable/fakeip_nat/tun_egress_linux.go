//go:build linux

package fakeipnat

// This file installs the linux side of the tun outlet: one default route in a
// dedicated table, plus an ip rule that sends every packet sourced from the
// fake range into it. Both commands are idempotent (replace, delete then add).

import (
	"context"
	"strconv"

	"go.uber.org/zap"
)

func (p *FakeIPNatPlugin) installTunEgressRoute(ctx context.Context) (func(), bool) {
	table := p.tunRouteTable
	if table == "" {
		table = "main"
	}
	// The outlet rule must win over the mark rule, so it gets the priority just
	// ahead of it; without mark routing there is nothing to race with and the
	// kernel default keeps the rule where it always was.
	prio := ""
	if p.markRoutingEnabled() && p.routeRulePriority > 1 {
		prio = strconv.Itoa(int(p.routeRulePriority - 1))
	}
	plan := tunRoutePlan(p.cidr, p.tunEgressHop, p.tunEgressDev, table, prio)
	if plan == nil {
		p.L().Warn("tun egress: neither gateway nor device is known, route table not installed")
		return nil, false
	}

	step, err := p.applyTunEgressPlan(ctx, plan)
	if err != nil {
		if step == "route" {
			p.L().Warn("tun egress: install default route failed",
				zap.String("table", table), zap.String("next_hop", p.tunEgressHop),
				zap.String("dev", p.tunEgressDev), zap.Error(err))
		} else {
			p.L().Warn("tun egress: add ip rule failed",
				zap.String("from", p.cidr), zap.String("table", table), zap.Error(err))
		}
		return nil, false
	}

	p.L().Info("tun egress: routing table installed",
		zap.String("table", table), zap.String("next_hop", p.tunEgressHop),
		zap.String("dev", p.tunEgressDev), zap.String("from", p.cidr),
		zap.String("prio", prio))

	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
		defer cancel()
		// Delete by the exact spec that was added, priority included, so a
		// policy rule of the host that happens to share the range cannot be
		// removed by mistake.
		del := egressRuleArgs("del", p.cidr, table, prio)
		_, _ = p.runner.Run(ctx, "ip", del...)
		_, _ = p.runner.Run(ctx, "ip", "route", "del", "default", "table", table)
		p.L().Debug("tun egress: routing table removed", zap.String("table", table), zap.String("from", p.cidr))
	}, true
}
