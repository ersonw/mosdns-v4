//go:build !linux && !darwin && !freebsd && !windows

package fakeipnat

import "context"

func readSystemDefaultRoute(ctx context.Context, runner cmdRunner) (hop, dev string) {
	return "", ""
}
