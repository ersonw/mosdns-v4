//go:build windows

package fakeipnat

import "context"

// readSystemDefaultRoute reads the IPv4 default route from route print. The
// interface column holds an address instead of a name, so only the gateway is
// usable as a next hop.
func readSystemDefaultRoute(ctx context.Context, runner cmdRunner) (hop, dev string) {
	if out, err := runner.Run(ctx, "route", "print", "-4"); err == nil {
		return parseWindowsDefaultRoute(out)
	}
	return "", ""
}
