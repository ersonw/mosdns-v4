//go:build !linux && !darwin

package fakeipnat

// Pinning the outlet to a gateway is not implemented on this platform, so the
// plugin keeps the host routing decision.

import "context"

func (p *FakeIPNatPlugin) installTunEgressRoute(ctx context.Context) (func(), bool) {
	p.L().Warn("tun egress: pinning the outlet to next_hop is not implemented on this platform")
	return nil, false
}
