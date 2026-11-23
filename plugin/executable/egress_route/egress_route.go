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
	"net"
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
	// the data-plane plugins: socks5, socks5h, http, https, trojan, gost and
	// cbp.
	//
	// cbp:// is the one scheme that is not a stream relay: CBP/1 carries raw
	// IPv4/IPv6 packets, so the outlet runs a userspace stack and dials TCP,
	// UDP and ICMP through a tunnel instead of handing one TCP connection to
	// the proxy. Its extra parameters ride in the URL query:
	//
	//	cbp://<edge-control>:<port>?identity_file=/etc/mosdns/cbp-client-identity.json
	//
	// Supported keys: token (or the URL userinfo), identity_file (required),
	// identity_server, identity_token, client_id, device_id, regions=a,b,
	// ca_file, sni, insecure=true and dial_timeout.
	//
	// identity_file accepts two shapes. A standalone edge's `cbpserver keygen`
	// bundle is nested and carries the client key, node auth token, CA path and
	// endpoints, so the URL may omit token and ca_file. A flat identity.json is
	// the central flow: when it is absent, identity_server issues the key pair
	// on first use and the result is cached in identity_file.
	//
	// A proxy exit owns no rule and no table: the socket that reaches the proxy
	// leaves through the host route, so mark and route_table may be left out.
	// That is what lets this plugin be the one place a data-plane plugin points
	// at for "send my flows through this proxy", with no kernel state involved.
	Proxy         string `yaml:"proxy"`
	ProxyInsecure bool   `yaml:"proxy_insecure"`
	// DirectFallback allows a failed proxy dial to leave from this box's own
	// address instead of failing. It defaults to true, which is what a general
	// browsing exit wants; a strict exit whose destinations must never appear
	// on the local address sets it to false.
	DirectFallback *bool `yaml:"direct_fallback"`
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
		// Marked traffic has to leave somewhere, and the proxy is not a routing
		// destination: the rule points at a table whose default route needs a
		// next hop or a device.
		if a.Mark != 0 && nextHop == "" && dev == "" {
			return fmt.Errorf("egress_route: a marked proxy exit still needs next_hop or next_hop_dev for the rule it installs")
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

	// Destinations are the other half of the mark: this exit decides which
	// addresses carry it, and a data path that resolves a name registers the
	// address here instead of writing its own chains.
	nft    *routepolicy.NFTInstaller
	set    string
	setTbl string
}

// Init builds the exit and installs it. Unlike the data-plane plugins this one
// must fail loudly: a half-installed exit is a routing hole, not a degraded
// feature, and the plugins that borrow it cannot work without it.
func Init(bp *coremain.BP, args interface{}) (coremain.Plugin, error) {
	cfg := args.(*Args)
	if strings.TrimSpace(cfg.NextHopDev) == "" && cfg.Mark != 0 {
		dev, err := systemDefaultRouteDev(context.Background())
		if err != nil {
			bp.L().Warn("egress_route: resolving the system default route device failed", zap.Error(err))
		} else {
			cfg.NextHopDev = dev
			bp.L().Info("egress_route: next_hop_dev resolved from the system default route",
				zap.String("dev", dev))
		}
	}
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
	directFallback := true
	if cfg.DirectFallback != nil {
		directFallback = *cfg.DirectFallback
	}
	p.L().Debug("egress_route: exit config",
		zap.Uint32("mark", cfg.Mark),
		zap.String("route_table", cfg.RouteTable),
		zap.Int("rule_priority", cfg.RulePriority),
		zap.String("nft_table", cfg.NFTable),
		zap.String("next_hop", cfg.NextHop),
		zap.String("next_hop_dev", cfg.NextHopDev),
		zap.String("proxy", egress.Redact(cfg.Proxy)),
		zap.String("proxy_from", cfg.ProxyFrom),
		zap.Bool("direct_fallback", directFallback))

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
		var d egress.Dialer
		var host string

		// A custom protocol plugin owns the first segment. The rest is
		// passed through verbatim; no URL parsing happens here, so a node
		// name such as "edge-sg-1" cannot be mistaken for a port.
		if pluginTag, params, ok := strings.Cut(raw, ":"); ok && pluginTag != "" {
			if provider := bp.M().GetProxyProvider(pluginTag); provider != nil {
				var err error
				d, host, err = provider.NewProxyDialer(params, cfg.ProxyInsecure)
				if err != nil {
					return nil, fmt.Errorf("egress_route: proxy provider %s: %w", pluginTag, err)
				}
				if strings.TrimSpace(host) == "" {
					return nil, fmt.Errorf("egress_route: proxy provider %s returned an empty proxy host", pluginTag)
				}
			} else {
				var err error
				d, err = egress.New(raw, cfg.ProxyInsecure)
				if err != nil {
					return nil, fmt.Errorf("egress_route: proxy: %w", err)
				}
				host = proxyHost(raw)
			}
		} else {
			var err error
			d, err = egress.New(raw, cfg.ProxyInsecure)
			if err != nil {
				return nil, fmt.Errorf("egress_route: proxy: %w", err)
			}
			host = proxyHost(raw)
		}

		probeStart := time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), defaultProbeTimeout)
		probeErr := egress.Probe(ctx, d)
		cancel()
		if probeErr != nil {
			p.L().Warn("egress_route: proxy probe failed",
				zap.String("proxy", egress.Redact(raw)), zap.String("exit", p.decision.String()),
				zap.Duration("elapsed", time.Since(probeStart)), zap.Error(probeErr))
			// A configured proxy is a policy decision: falling back to direct
			// would leak the traffic this exit exists to carry.
			return nil, fmt.Errorf("egress_route: proxy %s is not usable: %w", egress.Redact(raw), probeErr)
		}
		p.dialer = d
		p.proxy = host
		p.L().Debug("egress_route: proxy probe passed",
			zap.String("proxy", egress.Redact(raw)), zap.String("proxy_host", host),
			zap.Duration("elapsed", time.Since(probeStart)))
		p.L().Info("egress_route: proxy exit ready",
			zap.String("proxy", egress.Redact(raw)), zap.String("proxy_host", host), zap.String("exit", p.decision.String()))
		if cfg.DirectFallback != nil && !*cfg.DirectFallback {
			if !egress.SetNoDirectFallback(p.dialer) {
				p.L().Warn("egress_route: direct_fallback is false but this link is a single protocol and never falls back",
					zap.String("proxy", egress.Redact(raw)))
			} else {
				p.L().Info("egress_route: direct fallback disabled",
					zap.String("proxy", egress.Redact(raw)))
			}
		}
	} else {
		if p.decision.NextHop == "" && p.decision.Dev == "" {
			return nil, fmt.Errorf("egress_route: needs next_hop or next_hop_dev, or a proxy")
		}
		p.dialer = egress.NewDirect(p.decision.Dev, netip.Addr{})
		p.L().Info("egress_route: direct exit ready", zap.String("exit", p.decision.String()))
	}

	p.dialer = &loggingDialer{
		dialer: p.dialer,
		log:    p.L().With(zap.String("exit", p.decision.String())),
		exit:   p.decision.String(),
		proxy:  p.proxy,
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

	// A proxy exit that was also given a mark and a table is a routed exit that
	// happens to carry the proxy too: the rule is what sends marked traffic
	// somewhere, and the proxy only decides what the data path dials. Installing
	// it is therefore not conditional on the proxy - only the mark is.
	if p.decision.Mark != 0 {
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

	// A routed exit also owns the set its destinations are registered in, so a
	// borrowing data path writes no nft object of its own. The table may be
	// shared with the plugin that owns the destinations (asn_tun), which is why
	// the set and the chains are namespaced by this exit's tag and the table is
	// never deleted here.
	if p.installed && p.decision.NFTable != "" {
		ctx, cancel := context.WithTimeout(context.Background(), defaultProbeTimeout)
		set, err := routepolicy.NewNFTInstaller(execRunner{}).EnsureDestSet(ctx, bp.Tag(), p.decision, netip.Prefix{})
		cancel()
		if err != nil {
			// The route and the rule are already in place, so the exit still
			// works; only borrowers that register destinations are affected, and
			// they find out when they ask.
			p.L().Warn("egress_route: destination set not installed, borrowers must keep their own marking",
				zap.String("nft_table", p.decision.NFTable), zap.Error(err))
		} else {
			p.nft = routepolicy.NewNFTInstaller(execRunner{})
			p.set, p.setTbl = set, p.decision.NFTable
			p.L().Info("egress_route: destination set ready",
				zap.String("nft_table", p.setTbl), zap.String("set", p.set))
		}
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
	p.L().Debug("egress_route: closing exit", zap.String("exit", p.decision.String()))
	p.closeOnce.Do(func() {
		routepolicy.UnregisterOutlet(p.Tag())
		if p.dialer != nil {
			_ = egress.Close(p.dialer)
			p.dialer = nil
		}
		if p.set != "" {
			ctx, cancel := context.WithTimeout(context.Background(), defaultProbeTimeout)
			p.nft.RemoveDestSet(ctx, p.Tag(), p.setTbl)
			cancel()
			p.set = ""
		}
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

// loggingDialer records the per-connection outcome at Debug and the failures
// at Warn, without changing the outlet's behaviour. It deliberately does not
// implement Prober: the startup probe runs on the real outlet before wrapping.
type loggingDialer struct {
	dialer egress.Dialer
	log    *zap.Logger
	exit   string
	proxy  string
}

func (d *loggingDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	mode := "direct"
	if d.proxy != "" {
		mode = "proxy"
	}
	start := time.Now()
	d.log.Debug("egress_route: dialing",
		zap.String("mode", mode), zap.String("proxy_host", d.proxy),
		zap.String("network", network), zap.String("target", addr))
	conn, err := d.dialer.DialContext(ctx, network, addr)
	if err != nil {
		d.log.Warn("egress_route: dial failed",
			zap.String("mode", mode), zap.String("proxy_host", d.proxy),
			zap.String("network", network), zap.String("target", addr),
			zap.Duration("elapsed", time.Since(start)), zap.Error(err))
		return nil, err
	}
	d.log.Debug("egress_route: dial ready",
		zap.String("mode", mode), zap.String("proxy_host", d.proxy),
		zap.String("network", network), zap.String("target", addr),
		zap.Duration("elapsed", time.Since(start)))
	return conn, nil
}

func (d *loggingDialer) UnwrapDialer() egress.Dialer { return d.dialer }

func (d *loggingDialer) Close() error {
	return egress.Close(d.dialer)
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

// OutletDestSet names the set this exit marks destinations in, or empty when
// it carries no marking objects. A borrower reads it before asking to register
// anything: a proxy-only exit marks nothing and would only fail the call.
func (p *plugin) OutletDestSet() string { return p.set }

// MarkDestinations registers the addresses a borrower mapped to this exit.
//
// This is the non-tun half of the split: the data path turns a name into a real
// address and stops there, while the mark, the table and the route that send
// that address out remain this exit's, which is the only place they are
// written.
func (p *plugin) MarkDestinations(ctx context.Context, ips []string) error {
	if p.set == "" {
		return fmt.Errorf("egress_route: %s has no destination set, it cannot mark addresses", p.Tag())
	}
	return p.nft.AddDestinations(ctx, p.setTbl, p.set, ips)
}

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
