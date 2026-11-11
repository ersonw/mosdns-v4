//go:build !linux

package fakeipnat

import (
	"context"

	"go.uber.org/zap"
)

// listManagedRoutes is a no-op outside linux: the NAT data path there does not
// own an ip(8) routing table, so there is nothing to collapse.
func (p *FakeIPNatPlugin) listManagedRoutes(ctx context.Context, hop, dev string) []string {
	p.L().Debug("route aggregation: route scan is only implemented on linux",
		zap.String("next_hop", hop), zap.String("dev", dev))
	return nil
}
