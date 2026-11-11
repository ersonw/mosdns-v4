//go:build linux

package fakeipnat

import "context"

func readSystemDefaultRoute(ctx context.Context, runner cmdRunner) (hop, dev string) {
	if out, err := runner.Run(ctx, "ip", "route", "show", "default"); err == nil {
		hop, dev = parseIPRouteDefault(out)
		if hop != "" || dev != "" {
			return hop, dev
		}
	}
	// Fallback for images without iproute2 installed.
	if out, err := runner.Run(ctx, "route", "-n", "get", "default"); err == nil {
		return parseBSDDefaultRoute(out)
	}
	return "", ""
}
