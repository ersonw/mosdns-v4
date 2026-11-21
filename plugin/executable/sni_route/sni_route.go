package sni_route

// sni_route intercepts TCP connections on one interface, reads the TLS
// ClientHello, and sends the flow through the exit its server name selects.
//
// This plugin exists because a client that gets its addresses from its own
// HTTPDNS - or from an encrypted DNS tunnel the box cannot see - never asks
// this resolver, so a fake-IP data path has nothing to intercept. The server
// name is still visible in the clear at the start of a TCP handshake, and that
// is the one point where the decision can be made without trusting the client's
// resolver.

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ersonw/mosdns-v4/coremain"
	"github.com/ersonw/mosdns-v4/pkg/egress"
	"github.com/ersonw/mosdns-v4/pkg/executable_seq"
	"github.com/ersonw/mosdns-v4/pkg/query_context"
	"github.com/ersonw/mosdns-v4/pkg/routepolicy"
	"github.com/fsnotify/fsnotify"
	"go.uber.org/zap"
)

const PluginType = "sni_route"

const (
	defaultInterface  = "eth0"
	defaultSource     = "0.0.0.0/0"
	defaultNftTable   = "sni_route"
	defaultTunDev     = "sn0"
	defaultTunAddr    = "192.0.2.2/32"
	defaultTunMTU     = 1400
	defaultMark       = 130
	defaultRouteTable = "130"
	defaultRulePrio   = 1100
	defaultPort       = 443
	reloadDebounce    = 150 * time.Millisecond
)

var (
	validTableName = regexp.MustCompile(`^[a-zA-Z0-9_]+$`)
	validRouteName = regexp.MustCompile(`^[a-zA-Z0-9_.-]+$`)
	validTunName   = regexp.MustCompile(`^[a-zA-Z0-9_]{1,15}$`)
	validIfaceName = regexp.MustCompile(`^[a-zA-Z0-9_.:-]{1,15}$`)
)

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() interface{} { return new(Args) })
}

type Args struct {
	// Interface is the interface whose ingress is intercepted. Default eth0.
	Interface string `yaml:"interface"`
	// Source restricts interception to these client addresses. Empty means
	// 0.0.0.0/0, every client behind the interface.
	Source []string `yaml:"source"`
	// Ports are the TCP ports to intercept. Default 443. Only TCP is parsed;
	// QUIC is handled by BlockQUIC instead of a parser.
	Ports []int `yaml:"ports"`

	// Domain lists query_matcher plugin tags. A ClientHello server name is
	// matched by every listed matcher (logical OR), so a domain provider
	// already used by the resolver is reused here instead of duplicated.
	Domain []string `yaml:"domain"`
	// DomainFile is an optional file with one suffix per line. It is reloaded
	// when the file changes and is matched in addition to Domain tags.
	DomainFile string `yaml:"domain_file"`

	// BlockQUIC drops UDP/QUIC on the intercepted ports from the intercepted
	// clients, so the application falls back to TCP where the SNI is readable.
	// It is off by default: it changes behaviour for every captured client.
	BlockQUIC bool `yaml:"block_quic"`

	// Egress names an egress_route plugin that owns the matched exit. The
	// plugin must be declared before this one.
	Egress  string `yaml:"egress"`
	TunDev  string `yaml:"tun_dev"`
	TunAddr string `yaml:"tun_addr"`
	TunMTU  int    `yaml:"tun_mtu"`

	NftTable          string `yaml:"nft_table"`
	Mark              uint32 `yaml:"mark"`
	RouteTable        string `yaml:"route_table"`
	RouteRulePriority int    `yaml:"route_rule_priority"`

	// Bypass lists extra destination prefixes that must never enter the
	// device. Private ranges, the tun address and fake-IP ranges are always
	// bypassed.
	Bypass []string `yaml:"bypass"`
	// BypassIP accepts the same forms as response_matcher's ip field, including
	// "provider:<tag>" and "provider:<tag>:<category>". It is where a domestic
	// prefix list belongs, so local destinations keep their direct path while
	// only foreign destinations are captured.
	BypassIP []string `yaml:"bypass_ip"`
}

var _ coremain.ExecutablePlugin = (*Plugin)(nil)

type Plugin struct {
	*coremain.BP

	args   Args
	runner cmdRunner

	rules     ruleSet
	domains   []string
	matchers  []executable_seq.Matcher
	watcher   *fsnotify.Watcher
	watchDone chan struct{}

	iface   string
	sources []netip.Prefix
	bypass  []netip.Prefix
	ports   []int

	tunDev     string
	tunAddr    netip.Addr
	tunFile    *os.File
	tunCreated bool
	stack      *tunStack

	mark       uint32
	routeTable string
	rulePrio   int

	outlet      routepolicy.Outlet
	matched     egress.Dialer
	direct      egress.Dialer
	proxyActive bool

	runCtx        context.Context
	runCancel     context.CancelFunc
	wg            sync.WaitGroup
	closeOnce     sync.Once
	nftInstalled  bool
	routesStarted bool
}

func Init(bp *coremain.BP, args interface{}) (coremain.Plugin, error) {
	cfg := args.(*Args)
	p, err := newPlugin(bp, cfg)
	if err != nil {
		return nil, err
	}
	if err := p.start(); err != nil {
		// The DNS service must survive a data-plane add-on whose host
		// prerequisites are missing. Configuration errors already failed in
		// newPlugin.
		p.L().Error("sni_route: data plane setup failed, plugin disabled; DNS service continues", zap.Error(err))
		_ = p.Close()
		return p, nil
	}
	if m := bp.M(); m != nil {
		if sc := m.GetSafeClose(); sc != nil {
			sc.Attach(func(done func(), closeSignal <-chan struct{}) {
				defer done()
				<-closeSignal
				_ = p.Close()
			})
		}
	}
	return p, nil
}

func newPlugin(bp *coremain.BP, cfg *Args) (*Plugin, error) {
	iface := strings.TrimSpace(cfg.Interface)
	if iface == "" {
		iface = defaultInterface
	}
	if !validIfaceName.MatchString(iface) {
		return nil, fmt.Errorf("invalid interface %q", cfg.Interface)
	}

	sourceEntries := cfg.Source
	if len(sourceEntries) == 0 {
		sourceEntries = []string{defaultSource}
	}
	sources, err := parsePrefixes(sourceEntries)
	if err != nil {
		return nil, fmt.Errorf("source: %w", err)
	}

	ports, err := normalizePorts(cfg.Ports)
	if err != nil {
		return nil, err
	}

	tunDev := strings.TrimSpace(cfg.TunDev)
	if tunDev == "" {
		tunDev = defaultTunDev
	}
	if !validTunName.MatchString(tunDev) {
		return nil, fmt.Errorf("invalid tun_dev %q", cfg.TunDev)
	}
	tunAddr, err := parseTunAddr(cfg.TunAddr)
	if err != nil {
		return nil, err
	}
	mtu := cfg.TunMTU
	if mtu == 0 {
		mtu = defaultTunMTU
	}
	if mtu < 576 || mtu > 1500 {
		return nil, fmt.Errorf("invalid tun_mtu %d: must be 576..1500", mtu)
	}

	nftTable := strings.TrimSpace(cfg.NftTable)
	if nftTable == "" {
		nftTable = defaultNftTable
	}
	if !validTableName.MatchString(nftTable) || len(nftTable) > 32 {
		return nil, fmt.Errorf("invalid nft_table %q", nftTable)
	}
	mark := cfg.Mark
	if mark == 0 {
		mark = defaultMark
	}
	routeTable := strings.TrimSpace(cfg.RouteTable)
	if routeTable == "" {
		routeTable = defaultRouteTable
	}
	if routeTable == "main" || !validRouteName.MatchString(routeTable) {
		return nil, fmt.Errorf("invalid route_table %q: must be a dedicated table name", routeTable)
	}
	prio := cfg.RouteRulePriority
	if prio == 0 {
		prio = defaultRulePrio
	}
	if prio < 1 || prio >= 32766 {
		return nil, fmt.Errorf("invalid route_rule_priority %d: must be 1..32765", prio)
	}

	matchers, err := resolveMatchers(bp, cfg.Domain)
	if err != nil {
		return nil, fmt.Errorf("domain: %w", err)
	}

	// domain_file still carries a plain suffix list. It is optional and only
	// adds rules; the matcher tags above are the primary configuration.
	var domains []string
	if file := strings.TrimSpace(cfg.DomainFile); file != "" {
		entries, err := loadDomainFile(file)
		if err != nil {
			return nil, fmt.Errorf("read domain_file %q: %w", file, err)
		}
		domains = entries
	}
	p := &Plugin{
		BP:         bp,
		args:       *cfg,
		runner:     execRunner{},
		domains:    domains,
		matchers:   matchers,
		iface:      iface,
		sources:    sources,
		ports:      ports,
		tunDev:     tunDev,
		tunAddr:    tunAddr,
		mark:       mark,
		routeTable: routeTable,
		rulePrio:   prio,
	}
	if len(domains) > 0 {
		matcher, err := newDomainMatcher(domains)
		if err != nil {
			return nil, fmt.Errorf("domain_file: %w", err)
		}
		p.rules.Replace(matcher)
	}
	p.args.TunDev = tunDev
	p.args.TunAddr = tunAddr.String()
	p.args.TunMTU = mtu
	p.args.NftTable = nftTable
	p.args.Mark = mark
	p.args.RouteTable = routeTable
	p.args.RouteRulePriority = prio
	return p, nil
}

func parsePrefixes(entries []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	seen := make(map[netip.Prefix]struct{})
	for _, raw := range entries {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		var prefix netip.Prefix
		if strings.Contains(raw, "/") {
			parsed, err := netip.ParsePrefix(raw)
			if err != nil {
				return nil, fmt.Errorf("invalid prefix %q: %w", raw, err)
			}
			prefix = parsed
		} else {
			addr, err := netip.ParseAddr(raw)
			if err != nil {
				return nil, fmt.Errorf("invalid address %q: %w", raw, err)
			}
			prefix = netip.PrefixFrom(addr, addr.BitLen())
		}
		if prefix.Addr().Is4In6() {
			prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
		}
		if !prefix.Addr().Is4() {
			return nil, fmt.Errorf("only IPv4 is supported, got %q", raw)
		}
		prefix = prefix.Masked()
		if _, ok := seen[prefix]; ok {
			continue
		}
		seen[prefix] = struct{}{}
		out = append(out, prefix)
	}
	return out, nil
}

func normalizePorts(in []int) ([]int, error) {
	if len(in) == 0 {
		return []int{defaultPort}, nil
	}
	seen := make(map[int]struct{})
	var out []int
	for _, port := range in {
		if port < 1 || port > 65535 {
			return nil, fmt.Errorf("invalid port %d", port)
		}
		if _, ok := seen[port]; ok {
			continue
		}
		seen[port] = struct{}{}
		out = append(out, port)
	}
	return out, nil
}

func parseTunAddr(raw string) (netip.Addr, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		raw = defaultTunAddr
	}
	if !strings.Contains(raw, "/") {
		raw += "/32"
	}
	prefix, err := netip.ParsePrefix(raw)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("invalid tun_addr %q: %w", raw, err)
	}
	if !prefix.Addr().Is4() || prefix.Bits() != 32 {
		return netip.Addr{}, fmt.Errorf("tun_addr %q must be an IPv4 /32", raw)
	}
	if prefix.Addr().IsUnspecified() || prefix.Addr().IsMulticast() ||
		prefix.Addr().IsLoopback() || prefix.Addr().IsLinkLocalUnicast() {
		return netip.Addr{}, fmt.Errorf("tun_addr %q is not a usable host address", raw)
	}
	return prefix.Addr(), nil
}

func (p *Plugin) start() error {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	p.cleanupStaleState(ctx)

	if err := p.setupOutlet(); err != nil {
		return err
	}
	p.bypass = p.bypassAddresses()

	if err := p.setupTun(ctx); err != nil {
		return err
	}
	if err := p.installNft(ctx); err != nil {
		return err
	}
	p.routesStarted = true
	if err := p.installRoutes(ctx); err != nil {
		return err
	}
	if err := p.startStack(); err != nil {
		return err
	}

	p.runCtx, p.runCancel = context.WithCancel(context.Background())
	p.wg.Add(1)
	go p.safeGo("tun-reader", p.runTunDevice)
	p.wg.Add(1)
	go p.safeGo("stack-writer", p.runStackWriter)
	if file := strings.TrimSpace(p.args.DomainFile); file != "" {
		p.watchDomainFile(file)
	}

	p.L().Info("sni_route initialized",
		zap.String("interface", p.iface),
		zap.Int("source_count", len(p.sources)),
		zap.Ints("ports", p.ports),
		zap.Int("domain_rules", p.rules.Len()),
		zap.Int("domain_matchers", len(p.matchers)),
		zap.String("tun_dev", p.tunDev),
		zap.String("tun_addr", p.tunAddr.String()),
		zap.Uint32("mark", p.mark),
		zap.String("route_table", p.routeTable),
		zap.Bool("proxy_active", p.proxyActive),
		zap.Int("bypass_count", len(p.bypass)))
	return nil
}

func (p *Plugin) bypassAddresses() []netip.Prefix {
	// Private destinations, the device address and both fake-IP ranges are
	// always excluded. Without the fake ranges, traffic already routed through
	// fakeip_nat would be captured a second time and dialed as a literal
	// address, which is a loop.
	var out []netip.Prefix
	add := func(prefix netip.Prefix) {
		if prefix.IsValid() && prefix.Addr().Is4() {
			out = append(out, prefix.Masked())
		}
	}
	for _, raw := range []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
		"169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16",
		"198.16.0.0/15", "198.18.0.0/15",
		"224.0.0.0/4", "240.0.0.0/4",
	} {
		if prefix, err := netip.ParsePrefix(raw); err == nil {
			add(prefix)
		}
	}
	add(netip.PrefixFrom(p.tunAddr, 32))

	if extra, err := parsePrefixes(p.args.Bypass); err == nil {
		for _, prefix := range extra {
			add(prefix)
		}
	} else {
		p.L().Warn("sni_route: ignoring invalid bypass entry", zap.Error(err))
	}
	if len(p.args.BypassIP) > 0 {
		providerPrefixes, err := loadBypassProviders(p.BP, p.args.BypassIP)
		if err != nil {
			p.L().Warn("sni_route: loading bypass_ip failed", zap.Error(err))
		}
		for _, prefix := range providerPrefixes {
			add(prefix)
		}
	}

	// The socket that reaches the proxy must leave before the mark applies.
	host := ""
	if p.outlet != nil {
		host = p.outlet.OutletProxyHost()
	}
	if host != "" {
		ips, err := net.LookupIP(host)
		if err != nil {
			p.L().Warn("sni_route: resolve proxy host for bypass failed", zap.String("host", host), zap.Error(err))
		}
		for _, ip := range ips {
			if v4 := ip.To4(); v4 != nil {
				if addr, ok := netip.AddrFromSlice(v4); ok {
					add(netip.PrefixFrom(addr, 32))
				}
			}
		}
	}
	return uniquePrefixes(out)
}

func uniquePrefixes(in []netip.Prefix) []netip.Prefix {
	seen := make(map[netip.Prefix]struct{}, len(in))
	out := make([]netip.Prefix, 0, len(in))
	for _, prefix := range in {
		prefix = prefix.Masked()
		if _, ok := seen[prefix]; ok {
			continue
		}
		seen[prefix] = struct{}{}
		out = append(out, prefix)
	}
	return out
}

func (p *Plugin) watchDomainFile(path string) {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		p.L().Warn("sni_route: domain file watch failed", zap.String("file", path), zap.Error(err))
		return
	}
	// Watch the directory, not the file: an editor that replaces the file
	// removes the watch on the inode.
	dir := filepath.Dir(path)
	if err := w.Add(dir); err != nil {
		_ = w.Close()
		p.L().Warn("sni_route: domain file watch failed", zap.String("dir", dir), zap.Error(err))
		return
	}
	p.watcher = w
	p.watchDone = make(chan struct{})

	p.wg.Add(1)
	go p.safeGo("domain-watch", func() {
		defer p.wg.Done()
		defer close(p.watchDone)
		var timer *time.Timer
		reload := func() {
			entries, err := loadDomainFile(path)
			if err != nil {
				p.L().Warn("sni_route: reload domain_file failed, keeping the current list",
					zap.String("file", path), zap.Error(err))
				return
			}
			if len(entries) == 0 {
				p.rules.Replace(nil)
				p.L().Info("sni_route: domain_file empty, suffix rules disabled", zap.String("file", path))
				return
			}
			matcher, err := newDomainMatcher(entries)
			if err != nil {
				p.L().Warn("sni_route: domain_file has no usable rule, keeping the current list",
					zap.String("file", path), zap.Error(err))
				return
			}
			p.rules.Replace(matcher)
			p.L().Info("sni_route: domain_file reloaded",
				zap.String("file", path), zap.Int("domain_rules", matcher.len()))
		}
		for {
			select {
			case <-p.runCtx.Done():
				return
			case event, ok := <-w.Events:
				if !ok {
					return
				}
				if filepath.Clean(event.Name) != filepath.Clean(path) {
					continue
				}
				if event.Op&(fsnotify.Write|fsnotify.Create) == 0 {
					continue
				}
				if timer != nil {
					timer.Stop()
				}
				timer = time.AfterFunc(reloadDebounce, reload)
			case err, ok := <-w.Errors:
				if !ok {
					return
				}
				p.L().Warn("sni_route: domain file watch error", zap.Error(err))
			}
		}
	})
}

func (p *Plugin) runTunDevice() {
	defer p.wg.Done()
	buf := make([]byte, 65535)
	for {
		n, err := p.tunFile.Read(buf)
		if err != nil {
			if p.runCtx.Err() == nil {
				p.L().Warn("sni_route: tun read stopped", zap.Error(err))
			}
			return
		}
		if n == 0 {
			continue
		}
		p.safeInject(buf[:n])
	}
}

func (p *Plugin) runStackWriter() {
	defer p.wg.Done()
	for {
		pkt := p.stack.nextPacket(p.runCtx)
		if pkt == nil {
			return
		}
		if err := p.stack.writeOut(pkt); err != nil {
			if p.runCtx.Err() == nil {
				p.L().Debug("sni_route: tun write stopped", zap.Error(err))
			}
			return
		}
	}
}

func (p *Plugin) Exec(ctx context.Context, qCtx *query_context.Context, next executable_seq.ExecutableChainNode) error {
	return executable_seq.ExecChainNode(ctx, qCtx, next)
}

func (p *Plugin) Close() error {
	var err error
	p.closeOnce.Do(func() {
		if p.runCancel != nil {
			p.runCancel()
		}
		if p.watcher != nil {
			_ = p.watcher.Close()
		}
		if p.stack != nil {
			p.stack.close()
		}
		if p.tunFile != nil {
			_ = p.tunFile.Close()
		}
		if p.outlet == nil && p.matched != nil {
			_ = egress.Close(p.matched)
		}

		// Cleanup must not depend on the workers exiting. A stuck TUN read or
		// netstack writer would otherwise leave nft, rules, routes and the link
		// behind after a restart.
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		if p.routesStarted {
			p.cleanupRoutes(ctx)
		}
		if p.nftInstalled {
			if delErr := deleteNft(ctx, p.runner, p.args.NftTable); delErr != nil {
				p.L().Warn("sni_route: delete nft table failed", zap.Error(delErr))
				err = delErr
			}
		}
		p.cleanupTun(ctx)
		cancel()

		done := make(chan struct{})
		go func() {
			p.wg.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			p.L().Warn("sni_route: worker shutdown timed out after cleanup")
		}
	})
	return err
}

// cleanupStaleState reclaims objects a previous process may have left behind.
// The table, mark and route table names are dedicated to this plugin, so the
// reclaim is safe; a pre-existing TUN is removed only when those objects prove
// this plugin owned it.
func (p *Plugin) cleanupStaleState(ctx context.Context) {
	hadNft := p.nftTableExists(ctx, p.args.NftTable)
	hadRoute := p.routeTableExists(ctx, p.routeTable)
	if hadNft || hadRoute {
		p.L().Warn("sni_route: reclaiming stale state from a previous process",
			zap.String("nft_table", p.args.NftTable),
			zap.String("route_table", p.routeTable))
	}
	if err := p.removeAllRules(ctx); err != nil {
		p.L().Debug("sni_route: stale rule cleanup incomplete", zap.Error(err))
	}
	if err := p.removeRoutes(ctx); err != nil {
		p.L().Debug("sni_route: stale route cleanup incomplete", zap.Error(err))
	}
	if hadNft {
		if err := deleteNft(ctx, p.runner, p.args.NftTable); err != nil {
			p.L().Debug("sni_route: stale nft cleanup incomplete", zap.Error(err))
		}
	}
	_ = deleteNft(ctx, p.runner, p.args.NftTable+"_check")
	if hadNft || hadRoute {
		p.deleteTunLink(ctx)
	}
}

// String is only used in tests and diagnostics.
func (p *Plugin) String() string {
	return "sni_route:" + p.Tag() + ":" + strconv.FormatUint(uint64(p.mark), 10)
}
