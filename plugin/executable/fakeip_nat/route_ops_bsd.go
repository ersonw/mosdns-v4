//go:build darwin || freebsd

package fakeipnat

import (
	"context"

	"go.uber.org/zap"
)

// supportsNamedRouteTable reports whether the platform can write into a table
// other than main. BSD and macOS only have the one routing table.
func supportsNamedRouteTable() bool { return false }

// routeWriteCommands installs one route with route(8). Host routes use -host,
// aggregated blocks use -net plus the dotted netmask, because route(8) does not
// accept a CIDR on the command line.
func routeWriteCommands(prefix, hop, dev, table string) [][]string {
	addr, bits, ok := splitPrefix(prefix)
	if !ok {
		return nil
	}
	args := []string{"-n", "add"}
	if bits == 32 {
		args = append(args, "-host", addr)
	} else {
		args = append(args, "-net", addr, "-netmask", netmaskString(bits))
	}
	switch {
	case hop != "":
		args = append(args, "-gateway", hop)
	case dev != "":
		args = append(args, "-interface", dev)
	default:
		return nil
	}
	return [][]string{append([]string{"route"}, args...)}
}

// routeDeleteCommands removes one route. route(8) identifies a route by its
// destination, so the gateway is not part of the delete form.
func routeDeleteCommands(prefix, table string) [][]string {
	addr, bits, ok := splitPrefix(prefix)
	if !ok {
		return nil
	}
	args := []string{"-n", "delete"}
	if bits == 32 {
		args = append(args, "-host", addr)
	} else {
		args = append(args, "-net", addr, "-netmask", netmaskString(bits))
	}
	return [][]string{append([]string{"route"}, args...)}
}

// listManagedRoutes reads the IPv4 routing table through netstat. The table
// has a single view, so the configured route_table is ignored by design.
func (p *FakeIPNatPlugin) listManagedRoutes(ctx context.Context, hop, dev string) []string {
	out, err := p.runner.Run(ctx, "netstat", "-rn", "-f", "inet")
	if err != nil {
		p.L().Debug("route aggregation: list routes failed", zap.Error(err))
		return nil
	}
	routes := parseBSDManagedRoutes(out, hop, dev)
	p.L().Debug("route aggregation: managed routes scanned",
		zap.Int("count", len(routes)), zap.String("next_hop", hop), zap.String("dev", dev),
		zap.String("platform", "bsd"))
	return routes
}
