package asn_tun

import (
	"context"

	"go.uber.org/zap"
)

// setupOutlet wires the outlet this plugin sends its flows through.
//
// Two shapes reach here: an exit declared in this plugin's own args, or one lent
// by an egress_route plugin. Borrowing only rewires the fields the data plane
// already reads - dialer, mark, table, next hop, device - so the rest of the
// plugin cannot tell the difference, and the kernel state stays owned by one
// plugin.
func (p *ASNTunPlugin) setupOutlet(ctx context.Context) error {
	if p.outlet == nil {
		return p.setupEgress(ctx)
	}
	dec := p.outlet.OutletDecision()
	p.egress = p.outlet.OutletDialer()
	p.egressMark = dec.Mark
	p.egressTable = dec.Table
	p.nextHop = dec.NextHop
	p.nextHopDev = dec.Dev
	p.proxyActive = p.outlet.OutletProxyHost() != ""
	p.L().Info("asn_tun: exit borrowed from another plugin",
		zap.String("egress", p.outlet.OutletTag()),
		zap.String("exit", dec.String()),
		zap.Bool("proxy_active", p.proxyActive))
	return nil
}
