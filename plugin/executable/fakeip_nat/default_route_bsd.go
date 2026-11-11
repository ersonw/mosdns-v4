//go:build darwin || freebsd

package fakeipnat

import "context"

func readSystemDefaultRoute(ctx context.Context, runner cmdRunner) (hop, dev string) {
	if out, err := runner.Run(ctx, "route", "-n", "get", "default"); err == nil {
		hop, dev = parseBSDDefaultRoute(out)
		if hop != "" || dev != "" {
			return hop, dev
		}
	}
	// Fallback for hosts that also carry iproute2.
	if out, err := runner.Run(ctx, "ip", "route", "show", "default"); err == nil {
		return parseIPRouteDefault(out)
	}
	return "", ""
}
