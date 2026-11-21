package sni_route

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"syscall"

	"github.com/ersonw/mosdns-v4/pkg/egress"
	"github.com/ersonw/mosdns-v4/pkg/routepolicy"
	"go.uber.org/zap"
)

// markedDialer is the direct outlet when the borrowed exit is a routed one: the
// socket has to carry the exit's mark, otherwise it leaves through the main
// table and the exit is bypassed.
type markedDialer struct {
	mark uint32
	dev  string
}

func (d *markedDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	dialer := net.Dialer{}
	if d.mark != 0 || d.dev != "" {
		dialer.Control = func(_, _ string, c syscall.RawConn) error {
			return applySocketOptions(c, d.mark, d.dev)
		}
	}
	return dialer.DialContext(ctx, network, addr)
}

// dialerForOutlet turns a borrowed outlet into the two facts the data path
// needs: a dialer, and whether it can resolve a name itself. A proxy is the
// only outlet that can; giving a name to a direct outlet would send it right
// back into this box's resolver.
func (p *Plugin) dialerForOutlet(tag string) (egress.Dialer, bool, routepolicy.Decision, routepolicy.Outlet, error) {
	outlet, ok := routepolicy.OutletFor(tag)
	if !ok {
		return nil, false, routepolicy.Decision{}, nil, fmt.Errorf("egress %q is not loaded: declare the egress_route plugin before sni_route", tag)
	}
	dec := outlet.OutletDecision()
	if outlet.OutletProxyHost() != "" {
		return outlet.OutletDialer(), true, dec, outlet, nil
	}
	return &markedDialer{mark: dec.Mark, dev: dec.Dev}, false, dec, outlet, nil
}

func (p *Plugin) setupOutlet() error {
	// The matched path comes from an egress_route outlet. An exit that wants a
	// proxy binds one there; this plugin only borrows the resulting dialer.
	if tag := strings.TrimSpace(p.args.Egress); tag != "" {
		dialer, proxy, dec, outlet, err := p.dialerForOutlet(tag)
		if err != nil {
			return err
		}
		p.outlet = outlet
		p.matched = dialer
		p.proxyActive = proxy
		p.L().Info("sni_route: matched exit borrowed from another plugin",
			zap.String("egress", tag),
			zap.String("exit", dec.String()),
			zap.Bool("proxy_active", proxy))
	} else {
		p.matched = &markedDialer{}
		p.proxyActive = false
		p.L().Info("sni_route: matched flows use the direct path (no egress configured)")
	}

	// Unmatched flows are not this plugin's business. There is no default
	// exit and no device pin: the socket carries no mark and the host routing
	// table decides where it leaves.
	p.direct = egress.NewDirect("", netip.Addr{})
	p.L().Info("sni_route: unmatched flows use the system path")
	return nil
}
