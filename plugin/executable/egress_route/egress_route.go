// Package egress_route declares one exit as a plugin of its own: a mark, a
// routing table and a policy rule that send marked traffic to a next hop or a
// proxy.
//
// It exists because the same exit used to be written three times, once inside
// each data-plane plugin, with each copy owning its own mark and table. A
// plugin that needs an exit now borrows this one by tag instead, which is what
// keeps a single owner for one piece of kernel state.
package egress_route

import (
	"context"
	"fmt"
	"net/netip"
	"net/url"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/ersonw/mosdns-v4/coremain"
	"github.com/ersonw/mosdns-v4/pkg/egress"
	"github.com/ersonw/mosdns-v4/pkg/routepolicy"
	"go.uber.org/zap"
)

const PluginType = "egress_route"

const defaultProbeTimeout = 10 * time.Second

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() interface{} { return new(Args) })
}

// Args is one exit.
type Args struct {
	// Mark selects Table through a policy rule. It is the identity of the exit
	// in the kernel, so two exits cannot share it.
	Mark uint32 `yaml:"mark"`
	// NFTable names the nft table whose set decides which destinations carry
	// Mark. This plugin does not create it: the destinations belong to the
	// plugin that owns them, and naming the table here is what lets a reader
	// connect the mark back to its owner.
	NFTable string `yaml:"nft_table"`
	// RouteTable holds the single default route of this exit.
	RouteTable string `yaml:"route_table"`
	// RulePriority is the ip rule priority pointing at RouteTable.
	RulePriority int `yaml:"rule_priority"`
	// NextHop and NextHopDev describe where RouteTable sends the traffic. A
	// proxy exit uses neither: its marked sockets take the host route, and an
	// exit table would only send the proxy handshake somewhere else.
	NextHop    string `yaml:"next_hop"`
	NextHopDev string `yaml:"next_hop_dev"`
	// Proxy is the TCP outlet of this exit. Supported schemes are the same as
	// the data-plane plugins: socks5, socks5h, http, https, trojan and gost.
	//
	// A proxy exit owns no rule and no table: the socket that reaches the proxy
	// leaves through the host route, so mark and route_table may be left out.
	// That is what lets this plugin be the one place a data-plane plugin points
	// at for "send my flows through this proxy", with no kernel state involved.
	Proxy         string `yaml:"proxy"`
	ProxyInsecure bool   `yaml:"proxy_insecure"`
	// ProxyFrom borrows the proxy of another outlet instead of repeating the
	// link here. This is what lets one exit be both a routed exit (its own mark
	// and table) and a consumer of the box's single proxy definition: marks and
	// tables can never be shared, but the credentials and the endpoint can.
	// The named outlet must be declared before this one.
	ProxyFrom string `yaml:"proxy_from"`
}

// validate rejects an exit that cannot mean one thing. Half an exit is worse
// than a missing one: the borrower starts and its traffic goes somewhere the
// operator did not choose.
func (a *Args) validate() error {
	table := strings.TrimSpace(a.RouteTable)
	proxy := strings.TrimSpace(a.Proxy)
	nextHop := strings.TrimSpace(a.NextHop)
	dev := strings.TrimSpace(a.NextHopDev)

	if strings.TrimSpace(a.ProxyFrom) != "" {
		if proxy != "" {
			return fmt.Errorf("egress_route: proxy_from and proxy are mutually exclusive, name one place the link lives")
		}
		proxy = "borrowed"
	}
	if proxy != "" {
		// A proxy exit installs nothing, so a mark without a table (or the reverse)
		// would reserve kernel state that never appears.
		if a.Mark != 0 && table == "" {
			return fmt.Errorf("egress_route: mark needs route_table, or drop both for a proxy-only exit")
		}
		if a.Mark == 0 && table != "" {
			return fmt.Errorf("egress_route: route_table needs mark, or drop both for a proxy-only exit")
		}
		return nil
	}
	if a.Mark == 0 {
		return fmt.Errorf("egress_route: mark is required for a routed exit, it is how marked traffic finds this exit")
	}
	if table == "" {
		return fmt.Errorf("egress_route: route_table is required for a routed exit")
	}
	if nextHop == "" && dev == "" {
		return fmt.Errorf("egress_route: a routed exit needs next_hop or next_hop_dev")
	}
	return nil
}

type plugin struct {
	*coremain.BP

	args     *Args
	decision routepolicy.Decision
	dialer   egress.Dialer
	proxy    string

	installer *routepolicy.Installer
	installed bool
	claimed   bool
	closeOnce sync.Once
}

// Init builds the exit and installs it. Unlike the data-plane plugins this one
// must fail loudly: a half-installed exit is a routing hole, not a degraded
// feature, and the plugins that borrow it cannot work without it.
func Init(bp *coremain.BP, args interface{}) (coremain.Plugin, error) {
	cfg := args.(*Args)
	if err := cfg.validate(); err != nil {
		return nil, err
	}

	p := &plugin{
		BP:        bp,
		args:      cfg,
		installer: routepolicy.NewInstaller(execRunner{}),
		decision: routepolicy.Decision{
			Mark:     cfg.Mark,
			NFTable:  strings.TrimSpace(cfg.NFTable),
			Table:    strings.TrimSpace(cfg.RouteTable),
			Priority: cfg.RulePriority,
			NextHop:  strings.TrimSpace(cfg.NextHop),
			Dev:      strings.TrimSpace(cfg.NextHopDev),
		},
	}

	if from := strings.TrimSpace(cfg.ProxyFrom); from != "" {
		outlet, ok := routepolicy.OutletFor(from)
		if !ok {
			return nil, fmt.Errorf("egress_route: proxy_from %q is not declared before this plugin", from)
		}
		if outlet.OutletProxyHost() == "" {
			return nil, fmt.Errorf("egress_route: proxy_from %q is a direct exit, it has no proxy to borrow", from)
		}
		p.dialer = outlet.OutletDialer()
		p.proxy = outlet.OutletProxyHost()
		p.L().Info("egress_route: proxy borrowed from another outlet",
			zap.String("proxy_from", from), zap.String("proxy", p.proxy),
			zap.String("exit", p.decision.String()))
	}

	if raw := strings.TrimSpace(cfg.Proxy); raw != "" {
		d, err := egress.New(raw, cfg.ProxyInsecure)
		if err != nil {
			return nil, fmt.Errorf("egress_route: proxy: %w", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), defaultProbeTimeout)
		probeErr := egress.Probe(ctx, d)
		cancel()
		if probeErr != nil {
			// A configured proxy is a policy decision: falling back to direct
			// would leak the traffic this exit exists to carry.
			return nil, fmt.Errorf("egress_route: proxy %s is not usable: %w", egress.Redact(raw), probeErr)
		}
		p.dialer = d
		p.proxy = proxyHost(raw)
		p.L().Info("egress_route: proxy exit ready",
			zap.String("proxy", egress.Redact(raw)), zap.String("exit", p.decision.String()))
	} else {
		if p.decision.NextHop == "" && p.decision.Dev == "" {
			return nil, fmt.Errorf("egress_route: needs next_hop or next_hop_dev, or a proxy")
		}
		p.dialer = egress.NewDirect(p.decision.Dev, netip.Addr{})
		p.L().Info("egress_route: direct exit ready", zap.String("exit", p.decision.String()))
	}

	// A proxy-only exit writes nothing into the kernel, so there is no mark
	// for two plugins to fight over and nothing to claim.
	if p.proxy != "" && p.decision.Mark == 0 {
		if err := routepolicy.RegisterOutlet(p); err != nil {
			_ = p.Close()
			return nil, fmt.Errorf("egress_route: %w", err)
		}
		p.attachClose()
		p.L().Info("egress_route: proxy outlet registered, no kernel state",
			zap.String("exit", p.decision.String()))
		return p, nil
	}

	if err := routepolicy.Default().Claim(routepolicy.Claim{
		Owner: bp.Tag(), Mark: p.decision.Mark, Table: p.decision.Table, Priority: p.decision.Priority,
	}); err != nil {
		return nil, fmt.Errorf("egress_route: %w", err)
	}
	p.claimed = true

	// A proxy exit installs no rule: the sockets it owns leave through the host
	// route, and point them at a dedicated table would only lose the handshake.
	if p.proxy == "" {
		ctx, cancel := context.WithTimeout(context.Background(), defaultProbeTimeout)
		err := p.installer.Apply(ctx, p.decision)
		cancel()
		if err != nil {
			routepolicy.Default().Release(bp.Tag())
			return nil, fmt.Errorf("egress_route: install exit: %w", err)
		}
		p.installed = true
		p.L().Info("egress_route: exit installed",
			zap.String("exit", p.decision.String()), zap.String("nft_table", p.decision.NFTable))
	}

	if err := routepolicy.RegisterOutlet(p); err != nil {
		_ = p.Close()
		return nil, fmt.Errorf("egress_route: %w", err)
	}

	p.attachClose()
	return p, nil
}

// attachClose binds teardown to the manager's close signal, so a plugin that
// disappears also releases its tag and its kernel state.
func (p *plugin) attachClose() {
	if m := p.BP.M(); m != nil {
		if sc := m.GetSafeClose(); sc != nil {
			sc.Attach(func(done func(), closeSignal <-chan struct{}) {
				defer done()
				<-closeSignal
				_ = p.Close()
			})
		}
	}
}

func (p *plugin) Close() error {
	p.closeOnce.Do(func() {
		routepolicy.UnregisterOutlet(p.Tag())
		if p.installed {
			ctx, cancel := context.WithTimeout(context.Background(), defaultProbeTimeout)
			if err := p.installer.Remove(ctx, p.decision); err != nil {
				p.L().Warn("egress_route: exit cleanup incomplete", zap.Error(err))
			}
			cancel()
			p.installed = false
		}
		if p.claimed {
			routepolicy.Default().Release(p.Tag())
			p.claimed = false
		}
	})
	return nil
}

// OutletTag lets the borrower name its exit in a log line.
func (p *plugin) OutletTag() string { return p.Tag() }

// OutletDecision publishes what the borrower has to embed in its own log: the
// mark, table, priority and route this exit actually wrote.
func (p *plugin) OutletDecision() routepolicy.Decision { return p.decision }

// OutletDialer is the data path a borrower sends its flows through.
func (p *plugin) OutletDialer() egress.Dialer { return p.dialer }

// OutletProxyHost is the address a borrower must keep out of its own marking,
// because the socket that reaches the proxy cannot itself take the mark. The
// password stays here and never reaches the borrower's decision value.
func (p *plugin) OutletProxyHost() string { return p.proxy }

func proxyHost(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	h := u.Hostname()
	if ip, err := netip.ParseAddr(h); err == nil && ip.IsValid() {
		return ip.String()
	}
	return h
}

// execRunner is the production Runner: it shells out to `ip` the way the data
// plane plugins already do, so the exit behaves exactly as before.
type execRunner struct{}

func (execRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return string(out), err
}
