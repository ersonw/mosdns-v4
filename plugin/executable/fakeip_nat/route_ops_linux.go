//go:build linux

package fakeipnat

import (
	"context"
	"strings"

	"go.uber.org/zap"
)

// supportsNamedRouteTable reports whether the platform can write into a table
// other than main with the same command shape.
func supportsNamedRouteTable() bool { return true }

// routeWriteCommands installs one route. A named table is expressed with the
// "table" keyword, which is why linux keeps the single-table and multi-table
// cases on one branch.
func routeWriteCommands(prefix, hop, dev, table string) [][]string {
	args := []string{"route", "replace", prefix}
	if hop != "" {
		args = append(args, "via", hop)
	}
	if dev != "" {
		args = append(args, "dev", dev)
	}
	if table != "" && table != "main" {
		args = append(args, "table", table)
	}
	return [][]string{append([]string{"ip"}, args...)}
}

// routeDeleteCommands removes one route.
func routeDeleteCommands(prefix, table string) [][]string {
	args := []string{"route", "delete", prefix}
	if table != "" && table != "main" {
		args = append(args, "table", table)
	}
	return [][]string{append([]string{"ip"}, args...)}
}

// listManagedRoutes returns the IPv4 prefixes in the routing table that steer
// traffic to the configured gateway. The scan is deliberately conservative: a
// route is only a candidate when the hop (if configured) and the device appear
// on the entry. Without a hop only entries that carry an explicit gateway are
// considered, so the connected prefixes of the outlet are never mistaken for
// managed routes.
func (p *FakeIPNatPlugin) listManagedRoutes(ctx context.Context, hop, dev string) []string {
	args := []string{"-4", "route", "show"}
	if p.routeTable != "" && p.routeTable != "main" {
		args = append(args, "table", p.routeTable)
	}
	out, err := p.runner.Run(ctx, "ip", args...)
	if err != nil {
		p.L().Debug("route aggregation: list routes failed", zap.Error(err))
		return nil
	}

	var routes []string
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		prefix := fields[0]
		if !strings.Contains(prefix, "/") {
			continue
		}
		if hop != "" {
			if !hasField(fields, "via", hop) {
				continue
			}
		} else if !haveField(fields, "via") {
			continue
		}
		if dev != "" && !hasField(fields, "dev", dev) {
			continue
		}
		routes = append(routes, prefix)
	}
	p.L().Debug("route aggregation: managed routes scanned",
		zap.Int("count", len(routes)), zap.String("next_hop", hop), zap.String("dev", dev))
	return routes
}

func hasField(fields []string, key, value string) bool {
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] == key && fields[i+1] == value {
			return true
		}
	}
	return false
}

func haveField(fields []string, key string) bool {
	for _, f := range fields {
		if f == key {
			return true
		}
	}
	return false
}
