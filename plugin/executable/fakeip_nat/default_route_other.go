//go:build !linux && !darwin && !freebsd

package fakeipnat

import "context"

func readSystemDefaultRoute(ctx context.Context, runner cmdRunner) (hop, dev string) {
	return "", ""
}
