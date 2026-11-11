//go:build darwin

package fakeipnat

// Darwin has a single routing table and no ip rule equivalent, so a per-range
// table cannot be installed. The outlet is instead bound to the configured
// interface (IP_BOUND_IF) and to the range address.

import (
	"context"

	"go.uber.org/zap"
)

func (p *FakeIPNatPlugin) installTunEgressRoute(ctx context.Context) (func(), bool) {
	if p.tunEgressDev == "" {
		p.L().Warn("tun egress: darwin has no per-source routing table; set next_hop_dev to bind the outlet to that interface")
		return nil, false
	}
	p.L().Info("tun egress: darwin binds the outlet to the device instead of a route table",
		zap.String("dev", p.tunEgressDev), zap.String("source_range", p.cidr))
	return func() {}, true
}
