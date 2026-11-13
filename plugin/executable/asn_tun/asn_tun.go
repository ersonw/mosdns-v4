package asn_tun

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/ersonw/mosdns-v4/coremain"
	"github.com/ersonw/mosdns-v4/pkg/data_provider"
	"github.com/ersonw/mosdns-v4/pkg/executable_seq"
	"github.com/ersonw/mosdns-v4/pkg/helperscript"
	"github.com/ersonw/mosdns-v4/pkg/matcher/netlist"
	"github.com/ersonw/mosdns-v4/pkg/query_context"
	"github.com/ersonw/mosdns-v4/plugin/executable/fakeip_nat"
	"go.uber.org/zap"
)

const PluginType = "asn_tun"

const (
	defaultRefresh     = 12 * time.Hour
	defaultNftTable    = "asn_tun"
	defaultRouteTable  = "123"
	defaultTunDev      = "asn0"
	defaultTunAddr     = "192.0.2.1/32"
	defaultTunMTU      = 1500
	defaultProxyTunMTU = 1400
	defaultRulePrio    = 1000
	defaultFetchScript = "bgpq3_fetch_asn.py"
	defaultMergeScript = "cidr_merge.py"
	defaultPython      = "python3"
	refreshTimeout     = 5 * time.Minute
)

var (
	validTableName = regexp.MustCompile(`^[a-zA-Z0-9_]+$`)
	validRouteName = regexp.MustCompile(`^[a-zA-Z0-9_.-]+$`)
	validTunName   = regexp.MustCompile(`^[a-zA-Z0-9_]{1,15}$`)
	validMirrorDev = regexp.MustCompile(`^[a-zA-Z0-9_.:-]{1,15}$`)
)

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() interface{} { return new(Args) })
}

type Args struct {
	// ASN is the list whose announced IPv4 prefixes are routed into the device.
	ASN []uint32 `yaml:"asn"`

	// Source is the prefix provider: "ipverse" or "bgpq3".
	Source string `yaml:"source"`
	// Refresh reloads the prefixes on this interval. Zero disables periodic
	// refresh; the plugin still performs one asynchronous refresh at startup.
	Refresh string `yaml:"refresh"`
	// Cache stores the last successfully fetched prefix list. It is loaded
	// synchronously at startup, so a slow fetch or merge does not block the
	// data plane. A failed refresh keeps using the cached list.
	Cache string `yaml:"cache"`

	// These are used when source is "bgpq3". The fetch script writes one IPv4
	// prefix per line; the merge script aggregates all ASNs into one list.
	FetchScript string `yaml:"fetch_script"`
	MergeScript string `yaml:"merge_script"`
	Python      string `yaml:"python"`

	TunDev  string `yaml:"tun_dev"`
	TunAddr string `yaml:"tun_addr"`
	TunMTU  int    `yaml:"tun_mtu"`

	// MirrorDev restricts the prerouting mark rule to packets entering this
	// interface, for traffic copied from a switch mirror/SPAN port. Empty means
	// all interfaces, including the local output chain.
	MirrorDev string `yaml:"mirror_dev"`

	// SkipIP is an optional destination-address filter. Entries accept the
	// same forms as response_matcher's "ip" field, including "provider:<tag>"
	// and "provider:<tag>:<category>". Destinations matched here are skipped;
	// only unmatched destinations enter the ASN/TUN path.
	SkipIP []string `yaml:"skip_ip"`

	NftTable          string `yaml:"nft_table"`
	Mark              uint32 `yaml:"mark"`
	RouteTable        string `yaml:"route_table"`
	RouteRulePriority int    `yaml:"route_rule_priority"`

	// NextHop and NextHopDev define the direct outlet. Marked packets always
	// enter the device; the plugin's own sockets use EgressMark/EGressTable.
	NextHop    string `yaml:"next_hop"`
	NextHopDev string `yaml:"next_hop_dev"`
	// EgressMark selects the routing table for the plugin's direct sockets.
	EgressMark  uint32 `yaml:"egress_mark"`
	EgressTable string `yaml:"egress_table"`

	// Proxy is the TCP outlet. Supported schemes are the same as fakeip_nat:
	// socks5, socks5h, http, https, trojan and gost.
	Proxy         string `yaml:"proxy"`
	ProxyInsecure bool   `yaml:"proxy_insecure"`
}

type ASNTunPlugin struct {
	*coremain.BP

	args Args

	runner cmdRunner

	asns     []uint32
	prefixes []netip.Prefix
	bypass   []netip.Addr

	// skipPrefixes is generated from SkipIP. It is rendered into nft's skip4
	// set so matching destinations never get the ASN mark.
	skipPrefixes []netip.Prefix

	tunDev  string
	tunAddr netip.Addr
	tunFile *os.File
	// tunCreated records whether this instance created the link, so Close
	// removes only plugin-owned interfaces and leaves a pre-existing one alone.
	tunCreated bool
	stack      *tunStack

	mirrorDev string
	configDir string

	mark        uint32
	routeTable  string
	egressMark  uint32
	egressTable string
	rulePrio    int

	nextHop    string
	nextHopDev string

	egress      egressDialer
	proxyActive bool

	runCtx        context.Context
	runCancel     context.CancelFunc
	wg            sync.WaitGroup
	refreshMu     sync.Mutex
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
		_ = p.Close()
		return nil, err
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

func newPlugin(bp *coremain.BP, cfg *Args) (*ASNTunPlugin, error) {
	if len(cfg.ASN) == 0 {
		return nil, fmt.Errorf("asn is empty")
	}
	for _, asn := range cfg.ASN {
		if asn == 0 {
			return nil, fmt.Errorf("invalid asn 0")
		}
	}

	source := strings.ToLower(strings.TrimSpace(cfg.Source))
	switch source {
	case "":
		source = "ipverse"
	case "ipverse", "bgpq3":
	default:
		return nil, fmt.Errorf("unsupported source %q: use ipverse or bgpq3", cfg.Source)
	}

	configDir := ""
	if bp != nil && bp.M() != nil {
		configDir = bp.M().ConfigDir()
	}
	if configDir == "" {
		configDir, _ = os.Getwd()
	}

	fetchScript := helperscript.ConfiguredPath(configDir, cfg.FetchScript, defaultFetchScript)
	mergeScript := helperscript.ConfiguredPath(configDir, cfg.MergeScript, defaultMergeScript)
	python := strings.TrimSpace(cfg.Python)
	if python == "" {
		python = defaultPython
	}
	cachePath := strings.TrimSpace(cfg.Cache)
	if cachePath == "" {
		cachePath = defaultCache
	}

	refresh := defaultRefresh
	if strings.TrimSpace(cfg.Refresh) != "" {
		d, err := time.ParseDuration(cfg.Refresh)
		if err != nil || d < 0 {
			return nil, fmt.Errorf("invalid refresh %q", cfg.Refresh)
		}
		refresh = d
	}

	tunDev := strings.TrimSpace(cfg.TunDev)
	if tunDev == "" {
		tunDev = defaultTunDev
	}
	if !validTunName.MatchString(tunDev) {
		return nil, fmt.Errorf("invalid tun_dev %q", tunDev)
	}

	tunAddr, err := parseTunAddr(cfg.TunAddr)
	if err != nil {
		return nil, err
	}

	mirrorDev := strings.TrimSpace(cfg.MirrorDev)
	if mirrorDev != "" && !validMirrorDev.MatchString(mirrorDev) {
		return nil, fmt.Errorf("invalid mirror_dev %q", mirrorDev)
	}

	skipPrefixes, err := loadSkipPrefixes(bp, cfg.SkipIP)
	if err != nil {
		return nil, fmt.Errorf("load skip_ip: %w", err)
	}
	skipPrefixes = normalizePrefixes(skipPrefixes)

	nftTable := strings.TrimSpace(cfg.NftTable)
	if nftTable == "" {
		nftTable = defaultNftTable
	}
	if !validTableName.MatchString(nftTable) || len(nftTable) > 32 {
		return nil, fmt.Errorf("invalid nft_table %q", nftTable)
	}

	mark := cfg.Mark
	if mark == 0 {
		mark = 123
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

	egressMark := cfg.EgressMark
	if mark == ^uint32(0) {
		return nil, fmt.Errorf("invalid mark %d: must leave room for egress_mark", mark)
	}
	if egressMark == 0 {
		egressMark = mark + 1
	}
	if egressMark == mark {
		return nil, fmt.Errorf("egress_mark must differ from mark")
	}
	egressTable := strings.TrimSpace(cfg.EgressTable)
	if egressTable == "" {
		egressTable = "124"
	}
	if egressTable == "main" || !validRouteName.MatchString(egressTable) {
		return nil, fmt.Errorf("invalid egress_table %q", egressTable)
	}
	if egressTable == routeTable {
		return nil, fmt.Errorf("egress_table %q must differ from route_table", egressTable)
	}

	nextHop := strings.TrimSpace(cfg.NextHop)
	if nextHop != "" {
		if _, err := netip.ParseAddr(nextHop); err != nil {
			return nil, fmt.Errorf("invalid next_hop %q: %w", nextHop, err)
		}
	}
	nextHopDev := strings.TrimSpace(cfg.NextHopDev)
	if nextHopDev != "" && strings.ContainsAny(nextHopDev, " \t\r\n") {
		return nil, fmt.Errorf("invalid next_hop_dev %q", nextHopDev)
	}
	if nextHop == "" && nextHopDev == "" && strings.TrimSpace(cfg.Proxy) == "" {
		return nil, fmt.Errorf("no proxy and no next_hop/next_hop_dev: direct outlet has no route to install")
	}

	mtu := cfg.TunMTU
	if mtu == 0 {
		mtu = defaultTunMTU
		if strings.TrimSpace(cfg.Proxy) != "" {
			mtu = defaultProxyTunMTU
		}
	}
	if mtu < 576 || mtu > 1500 {
		return nil, fmt.Errorf("invalid tun_mtu %d: must be 576..1500", mtu)
	}

	p := &ASNTunPlugin{
		BP:           bp,
		args:         *cfg,
		runner:       execRunner{},
		asns:         append([]uint32(nil), cfg.ASN...),
		tunDev:       tunDev,
		tunAddr:      tunAddr,
		mirrorDev:    mirrorDev,
		configDir:    configDir,
		skipPrefixes: skipPrefixes,
		mark:         mark,
		routeTable:   routeTable,
		egressMark:   egressMark,
		egressTable:  egressTable,
		rulePrio:     prio,
		nextHop:      nextHop,
		nextHopDev:   nextHopDev,
	}
	p.args.TunMTU = mtu
	p.args.Refresh = refresh.String()
	p.args.Source = source
	p.args.Cache = cachePath
	p.args.FetchScript = fetchScript
	p.args.MergeScript = mergeScript
	p.args.Python = python
	p.args.NftTable = nftTable
	p.args.TunDev = tunDev
	p.args.TunAddr = tunAddr.String()
	p.args.MirrorDev = mirrorDev
	p.args.Mark = mark
	p.args.RouteTable = routeTable
	p.args.EgressMark = egressMark
	p.args.EgressTable = egressTable
	p.args.RouteRulePriority = prio
	return p, nil
}

func loadSkipPrefixes(bp *coremain.BP, entries []string) ([]netip.Prefix, error) {
	if len(entries) == 0 {
		return nil, nil
	}
	m := bp.M()
	var dm *data_provider.DataManager
	if m != nil {
		dm = m.GetDataManager()
	}
	return loadSkipPrefixesWithManager(dm, entries)
}

func loadSkipPrefixesWithManager(dm *data_provider.DataManager, entries []string) ([]netip.Prefix, error) {
	if len(entries) == 0 {
		return nil, nil
	}

	seen := make(map[netip.Prefix]struct{})
	var out []netip.Prefix
	add := func(list *netlist.List) {
		list.Sort()
		for _, prefix := range list.Prefixes() {
			if prefix.Addr().Is4In6() {
				prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
			}
			if !prefix.Addr().Is4() {
				continue
			}
			prefix = prefix.Masked()
			if _, ok := seen[prefix]; ok {
				continue
			}
			seen[prefix] = struct{}{}
			out = append(out, prefix)
		}
	}

	for _, raw := range entries {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		list := netlist.NewList()
		if strings.HasPrefix(raw, "provider:") {
			if dm == nil {
				return nil, fmt.Errorf("provider %s requires a data manager", raw)
			}
			name := strings.TrimPrefix(raw, "provider:")
			name, suffix, _ := strings.Cut(name, ":")
			provider := dm.GetDataProvider(name)
			if provider == nil {
				return nil, fmt.Errorf("cannot find provider %s", name)
			}
			data, err := provider.GetData()
			if err != nil {
				return nil, fmt.Errorf("read provider %s: %w", name, err)
			}
			if suffix != "" {
				list, err = netlist.ParseV2rayIPDat(data, suffix)
				if err != nil {
					return nil, fmt.Errorf("parse provider %s:%s: %w", name, suffix, err)
				}
			} else {
				if err := netlist.LoadFromReader(list, bytes.NewReader(data)); err != nil {
					return nil, fmt.Errorf("parse provider %s: %w", name, err)
				}
			}
		} else {
			if err := netlist.LoadFromText(list, raw); err != nil {
				return nil, fmt.Errorf("parse skip_ip %s: %w", raw, err)
			}
		}
		add(list)
	}
	final := netlist.NewList()
	final.Append(out...)
	final.Sort()
	out = out[:0]
	for _, prefix := range final.Prefixes() {
		if prefix.Addr().Is4In6() {
			prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
		}
		out = append(out, prefix)
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

func (p *ASNTunPlugin) start() error {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	prefixes, cacheErr := readPrefixCache(p.args.Cache, p.asns)
	if cacheErr != nil {
		p.L().Warn("asn_tun: no usable prefix cache; starting with an empty mark set until the async refresh completes",
			zap.String("cache", p.args.Cache), zap.Error(cacheErr))
		prefixes = nil
	} else {
		p.L().Info("asn_tun: prefix cache loaded",
			zap.Int("asn_count", len(p.asns)), zap.Int("prefix_count", len(prefixes)))
	}
	p.prefixes = prefixes

	// A previous process may have been killed before Close ran. Reclaim the
	// dedicated table/rule/route/TUN before creating the new instance, otherwise
	// a stale asn0 or rule makes every later start fail and leaves the old
	// objects in the packet path forever.
	p.cleanupStaleState(ctx)

	if err := p.setupEgress(ctx); err != nil {
		return err
	}
	p.bypass = p.bypassAddresses()

	if err := p.setupTun(ctx); err != nil {
		return err
	}
	if err := p.installNft(ctx); err != nil {
		return err
	}
	p.nftInstalled = true
	p.routesStarted = true
	if err := p.installRoutes(ctx); err != nil {
		return err
	}
	if err := p.startStack(); err != nil {
		return err
	}

	p.runCtx, p.runCancel = context.WithCancel(context.Background())
	initialPrefixCount := len(p.prefixes)
	initialSkipCount := len(p.skipPrefixes)
	p.wg.Add(1)
	go p.runTunDevice()
	p.wg.Add(1)
	go p.runStackWriter()
	p.wg.Add(1)
	go p.runStartupRefresh()

	if refresh := p.refreshInterval(); refresh > 0 {
		p.wg.Add(1)
		go p.runRefresh(refresh)
	}

	p.L().Info("asn_tun initialized",
		zap.Uint32s("asn", p.asns),
		zap.Int("prefix_count", initialPrefixCount),
		zap.String("tun_dev", p.tunDev),
		zap.String("tun_addr", p.tunAddr.String()),
		zap.String("mirror_dev", p.mirrorDev),
		zap.Int("skip_prefix_count", initialSkipCount),
		zap.Uint32("mark", p.mark),
		zap.String("route_table", p.routeTable),
		zap.Uint32("egress_mark", p.egressMark),
		zap.Bool("proxy_active", p.proxyActive),
		zap.Int("bypass_count", len(p.bypass)))
	return nil
}

func (p *ASNTunPlugin) refreshInterval() time.Duration {
	d, err := time.ParseDuration(p.args.Refresh)
	if err != nil || d <= 0 {
		return 0
	}
	return d
}

func (p *ASNTunPlugin) setupEgress(ctx context.Context) error {
	raw := strings.TrimSpace(p.args.Proxy)
	if raw == "" {
		p.egress = &directEgress{mark: p.egressMark, dev: p.nextHopDev}
		p.proxyActive = false
		p.L().Info("asn_tun: direct outlet", zap.Uint32("egress_mark", p.egressMark))
		return nil
	}

	proxy, err := fakeipnat.NewProxyEgress(raw, p.args.ProxyInsecure)
	if err != nil {
		return err
	}
	probeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := fakeipnat.ProbeEgress(probeCtx, proxy); err != nil {
		// A configured proxy is a policy decision, not a best-effort hint.
		// Silently switching to direct would leak traffic that the caller
		// explicitly asked to send through the proxy.
		return fmt.Errorf("proxy %s is not usable: %w", redactProxy(raw), err)
	}
	p.egress = proxy
	p.proxyActive = true
	p.L().Info("asn_tun: proxy outlet ready", zap.String("proxy", redactProxy(raw)))
	return nil
}

func (p *ASNTunPlugin) bypassAddresses() []netip.Addr {
	var out []netip.Addr
	add := func(s string) {
		addr, err := netip.ParseAddr(strings.TrimSpace(s))
		if err == nil && addr.Is4() {
			out = append(out, addr)
		}
	}
	add(p.nextHop)
	add(p.tunAddr.String())

	if p.proxyActive {
		host := proxyHost(p.args.Proxy)
		if host != "" {
			ips, err := net.LookupIP(host)
			if err != nil {
				p.L().Warn("asn_tun: resolve proxy host for bypass failed",
					zap.String("host", host), zap.Error(err))
			}
			for _, ip := range ips {
				if v4 := ip.To4(); v4 != nil {
					if addr, ok := netip.AddrFromSlice(v4); ok {
						out = append(out, addr)
					}
				}
			}
		}
	}
	return uniqueAddrs(out)
}

func (p *ASNTunPlugin) runStartupRefresh() {
	defer p.wg.Done()
	ctx, cancel := context.WithTimeout(p.runCtx, refreshTimeout)
	defer cancel()
	if err := p.refreshPrefixes(ctx); err != nil {
		p.L().Warn("asn_tun: startup prefix refresh failed, keeping the cached set", zap.Error(err))
	}
}

func (p *ASNTunPlugin) runRefresh(interval time.Duration) {
	defer p.wg.Done()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-p.runCtx.Done():
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(p.runCtx, refreshTimeout)
			err := p.refreshPrefixes(ctx)
			cancel()
			if err != nil {
				p.L().Warn("asn_tun: periodic refresh failed, keeping the current set", zap.Error(err))
			}
		}
	}
}

func (p *ASNTunPlugin) refreshPrefixes(ctx context.Context) error {
	p.refreshMu.Lock()
	defer p.refreshMu.Unlock()

	var prefixes []netip.Prefix
	var err error
	switch p.args.Source {
	case "bgpq3":
		prefixes, err = p.fetchPrefixesBGpq3(ctx)
	default:
		prefixes, err = p.fetchPrefixesIPVerse(ctx)
	}
	if err != nil {
		return fmt.Errorf("fetch ASN prefixes: %w", err)
	}
	if len(prefixes) == 0 {
		return fmt.Errorf("no IPv4 prefixes returned for ASN list")
	}
	prefixes = normalizePrefixes(prefixes)

	skip, skipErr := loadSkipPrefixes(p.BP, p.args.SkipIP)
	if skipErr != nil {
		p.L().Warn("asn_tun: reloading skip_ip failed, keeping the current skip set", zap.Error(skipErr))
		skip = p.skipPrefixes
	}
	skip = normalizePrefixes(skip)

	prefixChanged := !prefixesEqual(p.prefixes, prefixes)
	skipChanged := !prefixesEqual(p.skipPrefixes, skip)
	if !prefixChanged && !skipChanged {
		p.L().Info("asn_tun: prefix set unchanged",
			zap.String("source", p.args.Source),
			zap.Int("prefix_count", len(prefixes)),
			zap.Int("skip_prefix_count", len(skip)))
		return nil
	}

	oldPrefixes, oldSkip := p.prefixes, p.skipPrefixes
	p.prefixes = prefixes
	p.skipPrefixes = skip
	if err := p.installNft(ctx); err != nil {
		p.prefixes, p.skipPrefixes = oldPrefixes, oldSkip
		return fmt.Errorf("install refreshed nft set: %w", err)
	}
	if err := writePrefixCache(p.args.Cache, p.asns, prefixes); err != nil {
		p.L().Warn("asn_tun: writing prefix cache failed", zap.String("cache", p.args.Cache), zap.Error(err))
	}
	p.L().Info("asn_tun: prefix set updated",
		zap.String("source", p.args.Source),
		zap.Int("prefix_count", len(prefixes)),
		zap.Int("skip_prefix_count", len(skip)))
	return nil
}

func (p *ASNTunPlugin) runTunDevice() {
	defer p.wg.Done()
	buf := make([]byte, 65535)
	for {
		n, err := p.tunFile.Read(buf)
		if err != nil {
			if p.runCtx.Err() == nil {
				p.L().Warn("asn_tun: tun read stopped", zap.Error(err))
			}
			return
		}
		if n == 0 {
			continue
		}
		p.stack.inject(buf[:n])
	}
}

func (p *ASNTunPlugin) runStackWriter() {
	defer p.wg.Done()
	for {
		pkt := p.stack.nextPacket(p.runCtx)
		if pkt == nil {
			return
		}
		if err := p.stack.writeOut(pkt); err != nil {
			if p.runCtx.Err() == nil {
				p.L().Debug("asn_tun: tun write stopped", zap.Error(err))
			}
			return
		}
	}
}

func (p *ASNTunPlugin) Exec(ctx context.Context, qCtx *query_context.Context, next executable_seq.ExecutableChainNode) error {
	return executable_seq.ExecChainNode(ctx, qCtx, next)
}

func (p *ASNTunPlugin) Close() error {
	var err error
	p.closeOnce.Do(func() {
		if p.runCancel != nil {
			p.runCancel()
		}
		if p.stack != nil {
			p.stack.close()
		}
		if p.tunFile != nil {
			_ = p.tunFile.Close()
		}

		// Cleanup must not depend on the workers exiting. If a TUN read or
		// netstack writer is stuck, waiting here first would leave nft/rules/
		// routes/TUN behind after a systemd restart or failed start.
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		if p.routesStarted {
			p.cleanupRoutes(ctx)
		}
		if p.nftInstalled {
			if delErr := deleteNft(ctx, p.runner, p.args.NftTable); delErr != nil {
				p.L().Warn("asn_tun: delete nft table failed", zap.Error(delErr))
				err = delErr
			}
		}
		// The link is removed after the policy routes, otherwise deleting it
		// first would leave rules pointing at a nonexistent device.
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
			p.L().Warn("asn_tun: worker shutdown timed out after cleanup")
		}
	})
	return err
}

// cleanupStaleState removes objects that a previous process may have left
// behind. The table/rule/route names are dedicated to this plugin, so a
// startup reclaim is safe; a pre-existing TUN is removed only when the
// corresponding stale routing objects prove that this plugin owned it.
func (p *ASNTunPlugin) cleanupStaleState(ctx context.Context) {
	hadNft := p.nftTableExists(ctx, p.args.NftTable)
	hadRoute := p.routeTableExists(ctx, p.routeTable)
	hadEgressRoute := p.routeTableExists(ctx, p.egressTable)
	if hadNft || hadRoute || hadEgressRoute {
		p.L().Warn("asn_tun: reclaiming stale state from a previous process",
			zap.String("nft_table", p.args.NftTable),
			zap.String("route_table", p.routeTable),
			zap.String("egress_table", p.egressTable))
	}

	if err := p.removeAllRules(ctx); err != nil {
		p.L().Debug("asn_tun: stale rule cleanup incomplete", zap.Error(err))
	}
	if err := p.removeRoutes(ctx); err != nil {
		p.L().Debug("asn_tun: stale route cleanup incomplete", zap.Error(err))
	}
	if hadNft {
		if err := deleteNft(ctx, p.runner, p.args.NftTable); err != nil {
			p.L().Debug("asn_tun: stale nft cleanup incomplete", zap.Error(err))
		}
	}
	// A failed nft check never creates the throwaway table, but clean it if
	// an older build or an interrupted apply left one behind.
	_ = deleteNft(ctx, p.runner, p.args.NftTable+"_check")

	if hadNft || hadRoute || hadEgressRoute {
		p.deleteTunLink(ctx)
	}
}

func uniqueAddrs(in []netip.Addr) []netip.Addr {
	seen := make(map[netip.Addr]struct{}, len(in))
	out := make([]netip.Addr, 0, len(in))
	for _, a := range in {
		if !a.IsValid() {
			continue
		}
		if _, ok := seen[a]; ok {
			continue
		}
		seen[a] = struct{}{}
		out = append(out, a)
	}
	return out
}

func redactProxy(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "<empty>"
	}
	at := strings.LastIndex(raw, "@")
	if at < 0 {
		return raw
	}
	return raw[:at] + "@<redacted>"
}

func proxyHost(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	at := strings.LastIndex(raw, "@")
	if at >= 0 {
		raw = raw[at+1:]
	}
	if i := strings.Index(raw, "://"); i >= 0 {
		raw = raw[i+3:]
	}
	if i := strings.IndexAny(raw, "/?#"); i >= 0 {
		raw = raw[:i]
	}
	if i := strings.LastIndex(raw, ":"); i >= 0 {
		raw = raw[:i]
	}
	return raw
}
