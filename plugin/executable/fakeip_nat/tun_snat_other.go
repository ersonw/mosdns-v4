//go:build !linux && !darwin

package fakeipnat

import "context"

func (p *FakeIPNatPlugin) installTunSNAT(ctx context.Context) (func(), bool) {
	return nil, false
}
