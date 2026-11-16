package alias

// alias serves a domain list under a configurable suffix and routes the traffic
// that follows the answer. The list is a file this plugin owns (domain_file),
// not a data_provider, so nothing outside the plugin has to be reloaded when it
// changes: the bot edits the file through the plugin's admin methods and the
// served table is rebuilt in place.
//
// A query for "<real>.<suffix>" is answered immediately with a virtual address
// from ipv4_range; no upstream lookup happens at query time. The virtual
// address only carries the name. The outlet is decided when the first packet
// arrives on the own tun device: a working proxy gets "domain:port" and resolves
// nothing, a direct outlet resolves the name at that moment and dials it from
// the configured interface and next hop.

import (
	"context"
	"crypto/tls"
	"encoding/base32"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ersonw/mosdns-v4/coremain"
	outlet "github.com/ersonw/mosdns-v4/pkg/egress"
	"github.com/ersonw/mosdns-v4/pkg/executable_seq"
	"github.com/ersonw/mosdns-v4/pkg/matcher/domain"
	"github.com/ersonw/mosdns-v4/pkg/query_context"
	"github.com/miekg/dns"
	"go.uber.org/zap"
)

const PluginType = "alias"

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() interface{} { return new(Args) })
}

type Args struct {
	// DomainFile is the served domain list, one "[scheme://]domain" per line.
	// The plugin owns it: the bot edits it through the plugin, and every edit
	// reloads the table.
	DomainFile string `yaml:"domain_file"`

	// Suffix is appended to every served name, default "local".
	Suffix string `yaml:"suffix"`
	// ReplaceSuffix switches the name form. False appends ("ip138.com" ->
	// "ip138.com.local"); true replaces the last label ("ip138.com" ->
	// "ip138.local").
	ReplaceSuffix bool `yaml:"replace_suffix"`

	// AliasMode controls how the client-facing host is derived. "readable"
	// (default) keeps the real name in the alias; "opaque" encodes it as a
	// base32 label that does not resemble the real name, which avoids
	// browser lookalike-domain warnings.
	AliasMode string `yaml:"alias_mode"`

	// IPv4Range is the virtual segment, required.
	IPv4Range string `yaml:"ipv4_range"`
	TTL       uint32 `yaml:"ttl"`

	// UpstreamScheme is the default scheme used to reach a listed domain when
	// its own entry carries none. "http" (default), "https" or "auto".
	UpstreamScheme string `yaml:"upstream_scheme"`

	// AddForwardedHeaders adds X-Forwarded-Host/-For/-Proto to upstream
	// requests. Off by default: the upstream sees the gateway as the client.
	AddForwardedHeaders bool `yaml:"add_forwarded_headers"`

	// DotReplacement replaces every dot of the source domain before the
	// suffix is appended. Default "." keeps the name unchanged
	// (ip138.com.local); "-" flattens it to one label
	// (ip138-com.dyize.com), which a *.dyize.com wildcard can cover. A
	// replacement other than "." cannot be combined with replace_suffix.
	DotReplacement string `yaml:"dot_replacement"`

	// RedirectToAlias also serves the listed real names themselves and makes
	// plain HTTP for them answer 302 to the alias host (path and query kept).
	// Off by default: the list must not hijack names other plugins already
	// handle.
	RedirectToAlias bool `yaml:"redirect_to_alias"`

	// TLSCertFile and TLSKeyFile terminate TLS on port 443 with this pair.
	// When set, HTTPS requests go through the same gateway as HTTP and a
	// redirect uses https://<alias>. The certificate must cover every Host
	// that reaches 443 through the virtual addresses. Unset keeps 443
	// byte-transparent (the real certificate still validates).
	TLSCertFile string `yaml:"tls_cert_file"`
	TLSKeyFile  string `yaml:"tls_key_file"`

	TunDev string `yaml:"tun_dev"`
	TunMTU int    `yaml:"tun_mtu"`

	Proxy         string `yaml:"proxy"`
	ProxyInsecure bool   `yaml:"proxy_insecure"`

	NextHop      string `yaml:"next_hop"`
	NextHopDev   string `yaml:"next_hop_dev"`
	RouteTable   string `yaml:"route_table"`
	RulePriority int    `yaml:"rule_priority"`

	// Resolver is the plugin used to resolve a domain on the direct outlet.
	Resolver string `yaml:"resolver"`
}

var (
	_ coremain.ExecutablePlugin = (*plugin)(nil)
	_ coremain.MatcherPlugin    = (*plugin)(nil)
)

type plugin struct {
	*coremain.BP

	ttl       uint32
	replace   bool
	opaque    bool
	forwarded bool
	redirect  bool
	dotRepl   string
	defScheme string

	mu     sync.RWMutex
	suffix string // ".local", runtime editable
	store  *domainStore

	// aliasMu keeps the exact reverse mapping of generated readable alias
	// hosts. A flattened alias such as
	// "website-cdn-assets-ipinfo.aa2.dev" cannot be decoded unambiguously
	// because '-' is both the dot replacement and a valid label character.
	// Remembering the name when it is generated lets wildcard subdomains
	// under a listed suffix get their own real name and virtual address.
	aliasMu     sync.RWMutex
	aliasByName map[string]string // alias host -> real domain; "" = ambiguous

	alloc     *allocator
	prefix    netip.Prefix
	tlsConfig *tls.Config
	proxy     outlet.Dialer
	direct    *outlet.Direct
	resolve   *resolver

	plane *tunPlane
}

func Init(bp *coremain.BP, args interface{}) (coremain.Plugin, error) {
	cfg := args.(*Args)

	file := strings.TrimSpace(cfg.DomainFile)
	if file == "" {
		return nil, fmt.Errorf("alias: domain_file is required")
	}
	if st, err := os.Stat(file); err == nil && st.IsDir() {
		return nil, fmt.Errorf("alias: domain_file %s is a directory", file)
	}

	suffix := strings.TrimSpace(strings.ToLower(cfg.Suffix))
	suffix = strings.TrimPrefix(suffix, ".")
	if suffix == "" {
		suffix = "local"
	}
	if err := validateSuffix(suffix); err != nil {
		return nil, err
	}

	if strings.TrimSpace(cfg.IPv4Range) == "" {
		return nil, fmt.Errorf("alias: ipv4_range is required")
	}
	prefix, err := netip.ParsePrefix(strings.TrimSpace(cfg.IPv4Range))
	if err != nil {
		return nil, fmt.Errorf("alias: invalid ipv4_range: %w", err)
	}
	if !prefix.Addr().Is4() {
		return nil, fmt.Errorf("alias: ipv4_range %q must be IPv4", cfg.IPv4Range)
	}
	alloc, err := newAllocator(prefix)
	if err != nil {
		return nil, err
	}

	if prio := cfg.RulePriority; prio != 0 && (prio < 1 || prio > 32765) {
		return nil, fmt.Errorf("alias: rule_priority %d is outside 1..32765", prio)
	}
	if table := strings.TrimSpace(cfg.RouteTable); table != "" && !validRouteTable(table) {
		return nil, fmt.Errorf("alias: route_table %q is not a table name or number", table)
	}
	missingDev := ""
	if dev := strings.TrimSpace(cfg.NextHopDev); dev != "" && !deviceExists(dev) {
		// A missing interface is only fatal later, when a direct dial has to
		// bind to it; warn now instead of refusing to start.
		missingDev = dev
	}

	defScheme := strings.ToLower(strings.TrimSpace(cfg.UpstreamScheme))
	switch defScheme {
	case "":
		defScheme = schemeHTTP
	case schemeHTTP, schemeHTTPS, schemeAuto:
	default:
		return nil, fmt.Errorf("alias: upstream_scheme %q is not http, https or auto", cfg.UpstreamScheme)
	}

	tlsConfig, err := loadGatewayTLS(cfg.TLSCertFile, cfg.TLSKeyFile)
	if err != nil {
		return nil, err
	}

	store, err := loadDomainStore(file, defScheme)
	if err != nil {
		return nil, fmt.Errorf("alias: load %s: %w", file, err)
	}
	dotRepl, err := normalizeDotReplacement(cfg.DotReplacement)
	if err != nil {
		return nil, err
	}
	aliasMode := strings.ToLower(strings.TrimSpace(cfg.AliasMode))
	switch aliasMode {
	case "", "readable":
		aliasMode = "readable"
	case "opaque":
		if cfg.ReplaceSuffix {
			return nil, fmt.Errorf("alias: alias_mode opaque cannot be combined with replace_suffix")
		}
		if dotRepl == "." {
			// Long names that exceed one DNS label fall back to a readable
			// flattened label; dots therefore need a separator.
			dotRepl = "-"
		}
	default:
		return nil, fmt.Errorf("alias: alias_mode %q is not readable or opaque", cfg.AliasMode)
	}
	if dotRepl != "." {
		if err := checkFlattenCollision(store.listEntries(), dotRepl, cfg.ReplaceSuffix); err != nil {
			return nil, err
		}
	}

	ttl := cfg.TTL
	if ttl == 0 {
		ttl = 60
	}

	p := &plugin{
		BP:        bp,
		ttl:       ttl,
		suffix:    "." + suffix,
		replace:   cfg.ReplaceSuffix,
		opaque:    aliasMode == "opaque",
		forwarded: cfg.AddForwardedHeaders,
		redirect:  cfg.RedirectToAlias,
		dotRepl:   dotRepl,
		defScheme: defScheme,
		store:     store,
		alloc:     alloc,
		prefix:    prefix.Masked(),
		tlsConfig: tlsConfig,
	}

	direct := outlet.NewDirect(strings.TrimSpace(cfg.NextHopDev), netip.Addr{})
	direct.SetTimeout(dialTimeout)
	direct.SetLocal(alloc.deviceAddr())
	p.direct = direct

	p.preallocateStore()
	// Build the runtime aliases now, not on the first rewritten response:
	// the DNS query for a listed name can arrive before any page is fetched.
	// This also makes opaque and dot-flattened names resolvable immediately.
	p.rebuildAliasMappings()

	if raw := strings.TrimSpace(cfg.Proxy); raw != "" {
		proxy, perr := newProxyEgress(raw, cfg.ProxyInsecure, direct)
		if perr != nil {
			return nil, fmt.Errorf("alias: invalid proxy: %w", perr)
		}
		probeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := probeProxy(probeCtx, proxy); err != nil {
			p.log().Warn("alias: proxy is not usable, falling back to the direct outlet",
				zap.String("proxy", redactURL(raw)), zap.Error(err))
		} else {
			p.proxy = proxy
		}
		cancel()
	}

	if tag := strings.TrimSpace(cfg.Resolver); tag != "" {
		p.resolve = &resolver{tag: tag, parent: p.BP}
	}

	mtu := cfg.TunMTU
	if mtu == 0 {
		if p.proxy != nil {
			mtu = 1400
		} else {
			mtu = 1500
		}
	}
	if mtu < 576 || mtu > 1500 {
		return nil, fmt.Errorf("alias: tun_mtu %d is outside 576..1500", cfg.TunMTU)
	}

	if missingDev != "" {
		p.log().Warn("alias: next_hop_dev does not exist, direct dials will fail until it appears",
			zap.String("dev", missingDev))
	}

	plane, err := startTunPlane(p, cfg, prefix, alloc.deviceAddr(), uint32(mtu))
	if err != nil {
		return nil, err
	}
	p.plane = plane

	if p.tlsConfig != nil {
		p.log().Info("alias: tls gateway enabled",
			zap.String("cert", strings.TrimSpace(cfg.TLSCertFile)),
			zap.Strings("dns_names", p.tlsConfig.Certificates[0].Leaf.DNSNames),
			zap.Time("not_after", p.tlsConfig.Certificates[0].Leaf.NotAfter))
	}

	p.log().Info("alias ready",
		zap.String("file", file),
		zap.String("suffix", p.suffix),
		zap.Bool("replace_suffix", p.replace),
		zap.String("range", p.prefix.String()),
		zap.String("device_addr", alloc.deviceAddr().String()),
		zap.Int("domains", store.count()),
		zap.Int("aliases", p.aliasMappingCount()),
		zap.String("upstream_scheme", defScheme),
		zap.Bool("redirect_to_alias", p.redirect),
		zap.Bool("tls_gateway", p.tlsConfig != nil),
		zap.String("dot_replacement", p.dotRepl),
		zap.Bool("proxy_active", p.proxy != nil),
		zap.String("outlet_dev", strings.TrimSpace(cfg.NextHopDev)),
		zap.String("outlet_next_hop", strings.TrimSpace(cfg.NextHop)),
		zap.String("resolver", strings.TrimSpace(cfg.Resolver)))
	return p, nil
}

func deviceExists(dev string) bool {
	if _, err := os.Stat("/sys/class/net/" + dev); err == nil {
		return true
	}
	// Non-Linux hosts have no sysfs; do not reject the interface there.
	return runtime.GOOS != "linux"
}

func validRouteTable(t string) bool {
	for _, r := range t {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-':
		default:
			return false
		}
	}
	return len(t) <= 32
}

func validateSuffix(suffix string) error {
	if len(suffix) > 253 {
		return fmt.Errorf("alias: suffix %q is too long", suffix)
	}
	for _, label := range strings.Split(suffix, ".") {
		if label == "" || len(label) > 63 {
			return fmt.Errorf("alias: suffix %q contains an empty or oversized label", suffix)
		}
		for i, r := range label {
			switch {
			case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			case r == '-' && i > 0 && i < len(label)-1:
			default:
				return fmt.Errorf("alias: suffix %q is not a valid domain suffix", suffix)
			}
		}
	}
	return nil
}

// maxAliasMappings bounds the runtime reverse table. The virtual range is
// much smaller than this, and only generated alias names are recorded.
const maxAliasMappings = 65536

// rememberAlias records an exact alias-host -> real-domain mapping. It is
// called whenever aliasName renders a listed real host, so a wildcard
// subdomain that the client reaches through the gateway can later be
// resolved by its flattened alias host.
func (p *plugin) rememberAlias(alias, real string) {
	alias = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(alias)), ".")
	real = domain.NormalizeDomain(real)
	if alias == "" || real == "" || p.store == nil {
		return
	}
	if _, listed := p.store.matchName(real); !listed {
		return
	}
	p.aliasMu.Lock()
	defer p.aliasMu.Unlock()
	if p.aliasByName == nil {
		p.aliasByName = make(map[string]string)
	}
	if prev, ok := p.aliasByName[alias]; ok {
		if prev != real {
			// Two real hosts collapse to the same flattened label. Do not
			// silently proxy one of them with the other's Host.
			p.aliasByName[alias] = ""
			p.log().Debug("alias: runtime alias collision",
				zap.String("alias", alias), zap.String("previous", prev), zap.String("next", real))
		}
		return
	}
	if len(p.aliasByName) >= maxAliasMappings {
		return
	}
	p.aliasByName[alias] = real
	if p.alloc != nil {
		if _, err := p.alloc.Ensure(real); err != nil {
			p.log().Warn("alias: preallocate rewritten alias failed",
				zap.String("alias", alias), zap.String("domain", real), zap.Error(err))
		}
	}
}

func (p *plugin) lookupAlias(alias string) (real string, ok bool) {
	p.aliasMu.RLock()
	defer p.aliasMu.RUnlock()
	real, ok = p.aliasByName[strings.TrimSuffix(strings.ToLower(alias), ".")]
	return real, ok && real != ""
}

// lookup maps a served name back to the real domain and the scheme used to
// reach it.
func (p *plugin) lookup(qName string) (real, scheme string, ok bool) {
	name := domain.NormalizeDomain(qName)
	if mapped, ok := p.lookupAlias(name); ok {
		if p.store == nil {
			return mapped, "", true
		}
		if mappedScheme, served := p.store.matchName(mapped); served {
			return mapped, mappedScheme, true
		}
		return "", "", false
	}
	p.mu.RLock()
	suffix, replace, dotRepl, opaque := p.suffix, p.replace, p.dotRepl, p.opaque
	p.mu.RUnlock()

	if len(name) > len(suffix) && strings.HasSuffix(name, suffix) {
		stem := strings.TrimSuffix(name, suffix)
		if stem != "" && opaque {
			if real, scheme, ok := p.lookupOpaque(stem); ok {
				return real, scheme, true
			}
		}
		if stem != "" && dotRepl != "" && dotRepl != "." {
			if real, scheme, ok := p.lookupFlattened(stem, replace); ok {
				return real, scheme, true
			}
		} else if stem != "" {
			if !replace {
				if scheme, ok := p.store.matchName(stem); ok {
					return stem, scheme, true
				}
			} else {
				for _, label := range p.store.labelSet() {
					candidate := stem + "." + label
					if scheme, ok := p.store.matchName(candidate); ok {
						return candidate, scheme, true
					}
				}
			}
		}
	}
	// With redirect_to_alias the real name itself is served too, sharing the
	// same virtual address. Served suffixes cover their subdomains: a wildcard
	// subdomain gets its own exact name (and therefore its own virtual
	// address), not the parent's name.
	if p.redirect {
		if scheme, ok := p.store.matchName(name); ok {
			return name, scheme, true
		}
	}
	return "", "", false
}

// lookupFlattened maps a dot-free alias label back to the listed domain.
// Exact entries win; a subdomain alias keeps its prefix, which must not
// contain the replacement string (that would be a label separator and make
// the reverse mapping ambiguous).
// lookupOpaque decodes a base32 alias label and checks that the decoded name
// is actually served by this store. The store lookup prevents an arbitrary
// base32 string from turning the gateway into an open proxy.
func (p *plugin) lookupOpaque(stem string) (real, scheme string, ok bool) {
	decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(stem))
	if err != nil || len(decoded) == 0 {
		return "", "", false
	}
	name := domain.NormalizeDomain(string(decoded))
	if err := validateName(name); err != nil {
		return "", "", false
	}
	scheme, ok = p.store.matchName(name)
	if !ok {
		return "", "", false
	}
	return name, scheme, true
}

func (p *plugin) lookupFlattened(stem string, replace bool) (real, scheme string, ok bool) {
	if strings.Contains(stem, ".") {
		return "", "", false
	}
	exact := ""
	scheme = ""
	count := 0
	entries := p.store.listEntries()
	for _, e := range entries {
		target := e.Name
		if replace {
			target = stripLastLabel(target)
		}
		if flattenDomain(target, p.dotRepl) == stem {
			exact = e.Name
			scheme = e.Scheme
			count++
		}
	}
	if count == 1 {
		return exact, scheme, true
	}
	if count > 1 {
		// Two entries collapse to the same label: serve neither rather than
		// the wrong upstream Host.
		p.log().Warn("alias: dot_replacement collision, alias label is ambiguous",
			zap.String("label", stem), zap.Int("entries", count))
		return "", "", false
	}

	best := ""
	bestScheme := ""
	bestLen := 0
	for _, e := range entries {
		target := e.Name
		if replace {
			target = stripLastLabel(target)
		}
		flat := flattenDomain(target, p.dotRepl)
		if !strings.HasSuffix(stem, p.dotRepl+flat) {
			continue
		}
		prefix := stem[:len(stem)-len(flat)-len(p.dotRepl)]
		if prefix == "" || strings.Contains(prefix, p.dotRepl) {
			continue
		}
		if len(flat) > bestLen {
			best = strings.ReplaceAll(prefix, p.dotRepl, ".") + "." + e.Name
			bestScheme = e.Scheme
			bestLen = len(flat)
		}
	}
	if best == "" {
		return "", "", false
	}
	return best, bestScheme, true
}

func flattenDomain(name, repl string) string {
	if repl == "." || repl == "" {
		return name
	}
	return strings.ReplaceAll(name, ".", repl)
}

// stripLastLabel drops the final label used by replace_suffix. It leaves a
// single-label name untouched, matching the readable alias builder.
func stripLastLabel(name string) string {
	if idx := strings.LastIndexByte(name, '.'); idx > 0 {
		return name[:idx]
	}
	return name
}

// normalizeDotReplacement validates the separator substituted for dots. The
// default "." is a no-op; anything else must stay inside one DNS label.
func normalizeDotReplacement(raw string) (string, error) {
	raw = strings.ToLower(strings.TrimSpace(raw))
	if raw == "" || raw == "." {
		return ".", nil
	}
	if len(raw) > 16 {
		return "", fmt.Errorf("alias: dot_replacement %q is longer than 16 bytes", raw)
	}
	if strings.Contains(raw, ".") || strings.ContainsAny(raw, " \t\r\n") {
		return "", fmt.Errorf("alias: dot_replacement %q must not contain a dot or whitespace", raw)
	}
	for _, r := range raw {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
		default:
			return "", fmt.Errorf("alias: dot_replacement %q contains %q, only letters, digits, '-' and '_' are allowed", raw, r)
		}
	}
	return raw, nil
}

// checkFlattenCollision rejects a list where two entries collapse to the
// same flat label; their alias names would be indistinguishable.
func checkFlattenCollision(entries []entry, repl string, replace bool) error {
	seen := make(map[string]string, len(entries))
	for _, e := range entries {
		target := e.Name
		if replace {
			target = stripLastLabel(target)
		}
		flat := flattenDomain(target, repl)
		if prev, ok := seen[flat]; ok {
			return fmt.Errorf("alias: dot_replacement %q maps %q and %q to the same label %q", repl, prev, e.Name, flat)
		}
		seen[flat] = e.Name
	}
	return nil
}

// Match implements the matcher side with the same condition Exec applies.
func (p *plugin) Match(_ context.Context, qCtx *query_context.Context) (bool, error) {
	q := qCtx.Q()
	if q == nil || len(q.Question) != 1 {
		return false, nil
	}
	_, _, ok := p.lookup(q.Question[0].Name)
	return ok, nil
}

func (p *plugin) Exec(ctx context.Context, qCtx *query_context.Context, next executable_seq.ExecutableChainNode) error {
	q := qCtx.Q()
	if q == nil || len(q.Question) != 1 {
		return executable_seq.ExecChainNode(ctx, qCtx, next)
	}
	question := q.Question[0]
	real, _, ok := p.lookup(question.Name)
	if !ok {
		return executable_seq.ExecChainNode(ctx, qCtx, next)
	}

	// A real wildcard subdomain may be queried before its HTTP gateway flow
	// starts. Register its exact alias now so the alias host can be resolved
	// even when the client goes straight to the rewritten URL.
	p.aliasName(real)

	switch question.Qtype {
	case dns.TypeAAAA:
		// An AAAA answer would let the client bypass the virtual IPv4 path.
		resp := new(dns.Msg)
		resp.SetReply(q)
		resp.RecursionAvailable = true
		qCtx.SetResponse(resp)
		p.log().Debug("alias: aaaa answered empty", zap.String("name", question.Name))
		return nil
	case dns.TypeA:
	default:
		return executable_seq.ExecChainNode(ctx, qCtx, next)
	}

	addr, ok := p.alloc.Lookup(real)
	if !ok {
		var err error
		addr, err = p.alloc.Allocate(real)
		if err != nil {
			p.log().Error("alias: allocate virtual address failed",
				zap.String("domain", real), zap.Error(err))
			resp := new(dns.Msg)
			resp.SetReply(q)
			resp.Rcode = dns.RcodeServerFailure
			qCtx.SetResponse(resp)
			return nil
		}
	}
	resp := new(dns.Msg)
	resp.SetReply(q)
	resp.RecursionAvailable = true
	resp.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: p.ttl},
		A:   net.IP(addr.AsSlice()),
	}}
	qCtx.SetResponse(resp)
	p.log().Debug("alias: virtual address answered",
		zap.String("name", question.Name), zap.String("domain", real),
		zap.String("virtual_ip", addr.String()), zap.Uint32("ttl", p.ttl))
	return nil
}

// preallocateStore fills the runtime domain -> virtual address table from the
// current served list. It runs at startup and after every list reload, so the
// gateway always sees a mapping before it redirects or proxies a name.
func (p *plugin) preallocateStore() {
	entries := p.store.listEntries()
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name)
	}
	mapped, err := p.alloc.Preallocate(names)
	if err != nil {
		p.log().Warn("alias: preallocate domain mappings failed",
			zap.Int("mapped", mapped), zap.Int("domains", len(names)), zap.Error(err))
		return
	}
	p.log().Info("alias: domain mappings preallocated",
		zap.Int("domains", len(names)), zap.Int("mapped", mapped))
}

func (p *plugin) Close() error {
	if p.plane != nil {
		p.plane.stop()
	}
	return p.BP.Close()
}

// log returns a usable logger even in a unit test that built the plugin by hand
// without a BP; a nil zap logger would panic on first use.
func (p *plugin) log() *zap.Logger {
	if p.BP != nil {
		if l := p.BP.L(); l != nil {
			return l
		}
	}
	return zap.NewNop()
}

func dialHostPort(domainName string, port uint16) string {
	return net.JoinHostPort(domainName, strconv.Itoa(int(port)))
}
