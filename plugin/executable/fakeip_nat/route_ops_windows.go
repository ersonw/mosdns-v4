//go:build windows

package fakeipnat

import (
	"context"

	"go.uber.org/zap"
)

// supportsNamedRouteTable reports whether the platform can write into a table
// other than main. Windows keeps everything in the single IPv4 route table.
func supportsNamedRouteTable() bool { return false }

// routeWriteCommands installs one route with route.exe. route.exe selects the
// interface by index, not by name, so a route needs an explicit gateway here;
// without one there is nothing to steer and the write is skipped.
func routeWriteCommands(prefix, hop, dev, table string) [][]string {
	addr, bits, ok := splitPrefix(prefix)
	if !ok || hop == "" {
		return nil
	}
	return [][]string{{"route", "add", addr, "mask", netmaskString(bits), hop}}
}

// routeDeleteCommands removes the route that targets the given prefix.
func routeDeleteCommands(prefix, table string) [][]string {
	addr, _, ok := splitPrefix(prefix)
	if !ok {
		return nil
	}
	return [][]string{{"route", "delete", addr}}
}

// listManagedRoutes reads "route print -4" and keeps the entries whose next
// hop is the configured gateway.
func (p *FakeIPNatPlugin) listManagedRoutes(ctx context.Context, hop, dev string) []string {
	out, err := p.runner.Run(ctx, "route", "print", "-4")
	if err != nil {
		p.L().Debug("route aggregation: list routes failed", zap.Error(err))
		return nil
	}
	routes := parseWindowsManagedRoutes(out, hop, dev)
	p.L().Debug("route aggregation: managed routes scanned",
		zap.Int("count", len(routes)), zap.String("next_hop", hop), zap.String("dev", dev),
		zap.String("platform", "windows"))
	return routes
}
