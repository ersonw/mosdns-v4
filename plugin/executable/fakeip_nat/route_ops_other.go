//go:build !linux && !darwin && !freebsd && !windows

package fakeipnat

import (
	"context"

	"go.uber.org/zap"
)

// supportsNamedRouteTable reports whether the platform can write into a table
// other than main.
func supportsNamedRouteTable() bool { return false }

// routeWriteCommands is a no-op on platforms without a supported routing
// toolchain.
func routeWriteCommands(prefix, hop, dev, table string) [][]string { return nil }

// routeDeleteCommands is a no-op on platforms without a supported routing
// toolchain.
func routeDeleteCommands(prefix, table string) [][]string { return nil }

// listManagedRoutes has nothing to scan on unsupported platforms.
func (p *FakeIPNatPlugin) listManagedRoutes(ctx context.Context, hop, dev string) []string {
	p.L().Debug("route aggregation: route scan is not implemented on this platform",
		zap.String("next_hop", hop), zap.String("dev", dev))
	return nil
}
