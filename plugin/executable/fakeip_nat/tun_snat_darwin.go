//go:build darwin

package fakeipnat

// Darwin cannot bind a source address that belongs to another interface, so
// prepareDirectEgress keeps the host address on the outlet socket. That already
// is the post-rewrite state: the packet leaves with the host source and the
// gateway can answer it. No pf rule is installed, because a nat anchor only
// takes effect when /etc/pf.conf references it, and editing the system
// firewall config is not something a dns plugin should do behind the user's
// back.

import (
	"context"

	"go.uber.org/zap"
)

func (p *FakeIPNatPlugin) installTunSNAT(ctx context.Context) (func(), bool) {
	if p.proxyActive {
		p.L().Debug("tun snat: proxy carries the outlet, no host rewrite needed")
		return nil, false
	}
	p.L().Info("tun snat: outlet already sources from the host address (implicit snat)",
		zap.String("dev", p.tunEgressDev), zap.String("range", p.cidr))
	return func() {}, true
}
