package asn_tun

import (
	"context"
	"fmt"
	"strconv"

	"go.uber.org/zap"
)

func (p *ASNTunPlugin) installRoutes(ctx context.Context) error {
	if err := p.removeRoutes(ctx); err != nil {
		p.L().Debug("asn_tun: removing old routes failed", zap.Error(err))
	}

	// Marked packets enter the device; they never go straight to next_hop,
	// otherwise the userspace stack would never see the flow.
	if _, err := p.runner.Run(ctx, "ip", "route", "replace", "default", "dev", p.tunDev, "table", p.routeTable); err != nil {
		return fmt.Errorf("install device route: %w", err)
	}
	if _, err := p.runner.Run(ctx, "ip", p.ingressRuleArgs("del")...); err != nil {
		p.L().Debug("asn_tun: old ingress rule absent", zap.Error(err))
	}
	if _, err := p.runner.Run(ctx, "ip", p.ingressRuleArgs("add")...); err != nil {
		return fmt.Errorf("install ingress rule: %w", err)
	}

	if p.proxyActive {
		// The proxy is reached through the host's main route. An egress table
		// would only send the proxy handshake somewhere else.
		p.L().Debug("asn_tun: proxy carries the outlet, egress table not installed")
		return nil
	}
	if p.nextHop == "" && p.nextHopDev == "" {
		return fmt.Errorf("direct outlet has no next_hop or next_hop_dev")
	}
	args := []string{"route", "replace", "default"}
	if p.nextHop != "" {
		args = append(args, "via", p.nextHop)
	}
	if p.nextHopDev != "" {
		args = append(args, "dev", p.nextHopDev)
	}
	args = append(args, "table", p.egressTable)
	if _, err := p.runner.Run(ctx, "ip", args...); err != nil {
		return fmt.Errorf("install egress route: %w", err)
	}
	if _, err := p.runner.Run(ctx, "ip", p.egressRuleArgs("del")...); err != nil {
		p.L().Debug("asn_tun: old egress rule absent", zap.Error(err))
	}
	if _, err := p.runner.Run(ctx, "ip", p.egressRuleArgs("add")...); err != nil {
		return fmt.Errorf("install egress rule: %w", err)
	}

	p.L().Info("asn_tun: policy routes installed",
		zap.String("tun_dev", p.tunDev),
		zap.Uint32("mark", p.mark),
		zap.String("ingress_table", p.routeTable),
		zap.Uint32("egress_mark", p.egressMark),
		zap.String("egress_table", p.egressTable),
		zap.String("next_hop", p.nextHop),
		zap.String("next_hop_dev", p.nextHopDev))
	return nil
}

func (p *ASNTunPlugin) cleanupRoutes(ctx context.Context) {
	if err := p.removeRoutes(ctx); err != nil {
		// Missing rules/routes are expected when a previous run only installed
		// part of the policy. Keep the best-effort delete but leave a trace.
		p.L().Debug("asn_tun: route cleanup incomplete", zap.Error(err))
	}
}

func (p *ASNTunPlugin) removeRoutes(ctx context.Context) error {
	var first error
	for _, args := range [][]string{
		p.ingressRuleArgs("del"),
		p.egressRuleArgs("del"),
	} {
		if _, err := p.runner.Run(ctx, "ip", args...); err != nil && first == nil {
			first = err
		}
	}
	if _, err := p.runner.Run(ctx, "ip", "route", "del", "default", "table", p.routeTable); err != nil && first == nil {
		first = err
	}
	if _, err := p.runner.Run(ctx, "ip", "route", "del", "default", "table", p.egressTable); err != nil && first == nil {
		first = err
	}
	return first
}

func (p *ASNTunPlugin) ingressRuleArgs(action string) []string {
	return []string{
		"rule", action,
		"fwmark", strconv.FormatUint(uint64(p.mark), 10),
		"lookup", p.routeTable,
		"prio", strconv.Itoa(p.rulePrio),
	}
}

func (p *ASNTunPlugin) egressRuleArgs(action string) []string {
	prio := p.rulePrio + 1
	if prio > 32766 {
		prio = 32766
	}
	return []string{
		"rule", action,
		"fwmark", strconv.FormatUint(uint64(p.egressMark), 10),
		"lookup", p.egressTable,
		"prio", strconv.Itoa(prio),
	}
}
