package sni_route

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/ersonw/mosdns-v4/pkg/routepolicy"
	"go.uber.org/zap"
)

func (p *Plugin) installRoutes(ctx context.Context) error {
	if err := p.removeRoutes(ctx); err != nil {
		p.L().Debug("sni_route: removing old routes failed", zap.Error(err))
	}

	// Marked packets always enter the device; they must never be sent straight
	// to the exit, or the userspace stack would never see the ClientHello.
	if _, err := p.runner.Run(ctx, "ip", "route", "replace", "default", "dev", p.tunDev, "table", p.routeTable); err != nil {
		return fmt.Errorf("install device route: %w", err)
	}
	if _, err := p.runner.Run(ctx, "ip", p.ingressRuleArgs("del")...); err != nil {
		p.L().Debug("sni_route: old ingress rule absent", zap.Error(err))
	}
	if _, err := p.runner.Run(ctx, "ip", p.ingressRuleArgs("add")...); err != nil {
		return fmt.Errorf("install ingress rule: %w", err)
	}

	if err := routepolicy.Default().Claim(routepolicy.Claim{
		Owner: p.Tag(), Mark: p.mark, Table: p.routeTable, Priority: p.rulePrio,
	}); err != nil {
		p.L().Error("sni_route: routing object already owned", zap.Error(err))
	}

	p.L().Info("sni_route: policy route installed",
		zap.String("tun_dev", p.tunDev),
		zap.Uint32("mark", p.mark),
		zap.String("table", p.routeTable),
		zap.Int("priority", p.rulePrio))
	return nil
}

func (p *Plugin) cleanupRoutes(ctx context.Context) {
	if err := p.removeRoutes(ctx); err != nil {
		p.L().Debug("sni_route: route cleanup incomplete", zap.Error(err))
	}
}

func (p *Plugin) removeRoutes(ctx context.Context) error {
	var first error
	if _, err := p.runner.Run(ctx, "ip", p.ingressRuleArgs("del")...); err != nil && first == nil {
		first = err
	}
	if _, err := p.runner.Run(ctx, "ip", "route", "del", "default", "table", p.routeTable); err != nil && first == nil {
		first = err
	}
	return first
}

func (p *Plugin) routeTableExists(ctx context.Context, table string) bool {
	_, err := p.runner.Run(ctx, "ip", "route", "show", "table", table)
	return err == nil
}

// removeAllRules removes duplicate rules this instance may have left on an
// earlier start. A single "ip rule del" would leave the rest in the packet path.
func (p *Plugin) removeAllRules(ctx context.Context) error {
	out, err := p.runner.Run(ctx, "ip", "rule", "show")
	if err != nil {
		return err
	}
	count := 0
	markHex := fmt.Sprintf("fwmark 0x%x", p.mark)
	tableLookup := "lookup " + p.routeTable
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, markHex) && strings.Contains(line, tableLookup) {
			count++
		}
	}
	if count == 0 {
		return nil
	}
	var first error
	for i := 0; i < count; i++ {
		if _, err := p.runner.Run(ctx, "ip", p.ingressRuleArgs("del")...); err != nil {
			if first == nil {
				first = err
			}
			break
		}
	}
	return first
}

func (p *Plugin) ingressRuleArgs(action string) []string {
	return []string{
		"rule", action,
		"fwmark", strconv.FormatUint(uint64(p.mark), 10),
		"lookup", p.routeTable,
		"prio", strconv.Itoa(p.rulePrio),
	}
}
