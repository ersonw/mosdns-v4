package fakeipnat

import (
	"context"
	"database/sql"
	"encoding/binary"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/ersonw/mosdns-v4/coremain"
	"github.com/ersonw/mosdns-v4/pkg/executable_seq"
	"github.com/ersonw/mosdns-v4/pkg/query_context"
	"github.com/miekg/dns"
	"go.uber.org/zap"
	_ "modernc.org/sqlite"
)

const PluginType = "fakeip_nat"

// pendingFakeIP marks a mapping row that has an id but no allocated address yet.
// It is only visible between the INSERT and the UPDATE inside recordAndAllocate,
// or after a crash in that window.
const pendingFakeIP = "pending"

// defaultTaskConcurrency caps how many NAT tasks run at the same time.
const defaultTaskConcurrency = 8

var validTableName = regexp.MustCompile(`^[a-zA-Z0-9_]+$`)

// route tables are either a name (main, oversea) or an iproute2 id.
var validRouteTable = regexp.MustCompile(`^[a-zA-Z0-9_.-]+$`)

// validHostLabel keeps hop_name_suffix a single DNS label.
var validHostLabel = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() interface{} { return new(Args) })
}

type Args struct {
	DBPath      string `yaml:"db_path"`      // SQLite 路径，默认: "/config/mosdns/fakeip.db"
	TablePrefix string `yaml:"table_prefix"` // 数据库表名前缀，默认: "default"
	IPv4Range   string `yaml:"ipv4_range"`   // 虚拟 IP 段，默认: "198.18.0.0/15"
	TTL         uint32 `yaml:"ttl"`          // 返回的 DNS TTL，默认: 60
	// RecordTTL 是域名映射的保留时长，默认 "168h"（7 天）。超过该时长没有被查询过的
	// 记录会被后台任务从 SQLite 和内存中删除，释放的虚拟地址重新进入可分配池。
	// 填 "0" 关闭清理（记录一直保留）。支持 Go 时长语法：168h、24h、30m。
	RecordTTL  string `yaml:"record_ttl"`
	NextHop    string `yaml:"next_hop"`     // 可选：NAT 模式下真实目标 IP 的下一跳网关（不填则用系统默认路由）
	NextHopDev string `yaml:"next_hop_dev"` // 可选：NAT 模式下下一跳出站网卡名称（不填则不指定 dev）

	// RealIP 切换 DNS 答复的内容，默认 false。
	// false：分配虚拟 IP、建立 DNAT 映射，并把虚拟 IP 回复给客户端；映射成功
	// 之后才回复，避免客户端拿到虚拟 IP 时数据面还没准备好。
	// true：不分配虚拟 IP、不写 DNAT 映射，DNS 直接回复真实 IP，只给解析出来
	// 的真实 IP 写一条到出口的 host route（等价于纯路由分流）。
	RealIP bool `yaml:"realip"`

	// Script 已废弃：脚本回调已移除，保留字段只是为了让带 script 的旧配置仍能启动。
	Script string `yaml:"script"`

	// MSSClamp 用于 NAT 数据面：在 nft 里给经过本机的 SYN / SYN-ACK 改写 MSS
	// 选项，避免客户端按 1500 的链路 MTU 协商出 1460 字节的段，而出口隧道
	// （wg 常见 1400）接不住，表现为握手成功但网页卡死在传输阶段。
	// 0 表示关闭（默认，行为不变）。建议填隧道 MTU 减 40，例如 1400 -> 1360。
	// 只在 fake-ip 的 nft 表里生效：tun 数据面由 tun_mtu 负责，realip 模式没有表。
	MSSClamp int `yaml:"mss_clamp"`

	// NAT 数据面（默认）：插件直接管理 nftables DNAT 与 host route。
	RouteTable      string `yaml:"route_table"`       // host route 写入的路由表，默认: "main"
	AggregateRoutes *bool  `yaml:"route_aggregation"` // 是否把 /32 host route 做严格 CIDR 聚合，默认: true

	// UseTun 打开 TUN 数据面：向系统申请 tun 网卡，并在主表把 ipv4_range 路由到
	// 该网卡。默认 false，即使用内置 NAT。
	UseTun bool `yaml:"use_tun"`
	// TunDev 指定 tun 设备名。留空则由插件自己申请，按 mth0、mth1… 的顺序取第一个
	// 空闲名字（上次遗留且地址仍是段首地址的同名设备会被复用）；非空时优先复用
	// 同名设备，不存在才创建。
	TunDev string `yaml:"tun_dev"`
	// TunMTU 是 tun 设备的 MTU，也就是本插件向客户端通告的分段大小上限。
	// 0 表示自动：直连出口用 1500；代理出口用 1400，因为代理链路还套着一层
	// 隧道（wg 常见 1420），1500 的段会被丢掉，表现为握手通、网页卡住。
	// 显式值优先于自动选择，范围 576..1500。
	TunMTU int `yaml:"tun_mtu"`

	// Proxy 是 tun 数据面的出站代理链接，例如
	// socks5://user:pass@host:1080、http://host:8080、trojan://pass@host:443?sni=host。
	// 留空则直连；传入且探测通过才作为出口，探测失败会回退直连并报错日志。
	Proxy string `yaml:"proxy"`
	// ProxyInsecure 跳过 https / trojan 代理的证书校验，供自签证书使用。
	ProxyInsecure bool `yaml:"proxy_insecure"`

	// HopNameSuffix 是路由探测时给每一跳分配的反向解析后缀，默认复用 table_prefix
	// （下划线换成连字符）：
	// 虚拟地址的 PTR 记录返回 "<真实跳地址>.<后缀>"，下游 traceroute 因此能
	// 同时看到真实下一跳和发给它的虚拟地址。只允许字母、数字和连字符。
	HopNameSuffix string `yaml:"hop_name_suffix"`

	// TunRouteTable 是 tun 数据面直连时新建的路由表，默认 "100"。插件在该表里
	// 写一条 default 路由（via next_hop / dev next_hop_dev），并用
	// `ip rule from <ipv4_range> lookup <table>` 把段内源地址的流量导进去。
	// 配了代理时不会建表。仅 Linux 支持独立路由表；darwin 改为把出口 socket
	// 绑定到 next_hop_dev。
	TunRouteTable string `yaml:"tun_route_table"`
}

type FakeIPNatPlugin struct {
	*coremain.BP
	db            *sql.DB
	dbPath        string
	tablePrefix   string
	mapTable      string
	ipTable       string
	cidr          string
	prefix        netip.Prefix
	maxHosts      uint64 // usable address count inside prefix, broadcast and network excluded
	ttl           uint32
	recordTTL     time.Duration
	retentionStop chan struct{}
	retentionOnce sync.Once
	nextHop       string
	nextHopDev    string
	// realIP mirrors Args.RealIP: when set the plugin answers real IPs and only
	// maintains the host routes that steer them out of the chosen gateway.
	realIP bool
	mu     sync.Mutex // serializes fake ip allocation

	taskSem      chan struct{}       // bounds concurrently running NAT tasks
	taskMu       sync.Mutex          // guards taskInFlight
	taskInFlight map[string]struct{} // domains whose NAT task is running

	// NAT data path: the plugin owns the nftables map and host routes.
	routeTable      string
	aggregateRoutes bool
	// mssClamp is the MSS value written into SYN / SYN-ACK packets, 0 to leave
	// the negotiated value alone.
	mssClamp int
	// realRoutes is the set of real IPs that already carry a /32 host route in
	// realip mode. It is informational only: aggregation re-reads the routing
	// table, so routes written by an earlier process are also collapsed.
	realMu     sync.Mutex
	realRoutes map[string]struct{}
	// aggMu guards the aggregation loop handles. The loop re-reads the routing
	// table on every tick instead of relying on anything tracked in memory.
	aggMu   sync.Mutex
	aggStop chan struct{}
	aggDone chan struct{}
	natMu   sync.Mutex // serializes nft / ip command sequences
	runner  cmdRunner
	probe   func(ctx context.Context, ip string) bool

	// TUN data path: the whole ipv4_range is routed to a device requested from
	// the system instead of being DNAT-ed hop by hop.
	useTun bool
	tunDev string
	// tunMTU is the MTU written to the device and advertised by the stack. It
	// is resolved once in Init from tun_mtu, or from the outlet kind.
	tunMTU uint32
	// egress is the outlet of the tun data path: direct by default, or a
	// socks5 / http / trojan proxy when `proxy` is configured and reachable.
	egress egressDialer
	// proxyActive reports whether egress is a proxied outlet. It decides the
	// target handed to it: the domain when proxied, the real IP when direct.
	proxyActive bool

	// Tun outlet routing: a dedicated table keeps the fake range out of the
	// host default route, so only the new sockets opened for a flow leave
	// through next_hop, and the host's own traffic is untouched.
	tunRouteTable    string
	tunEgressHop     string
	tunEgressDev     string
	tunEgressCleanup func()

	// ICMP relay of the tun data path: echo requests are forwarded to the real
	// ip, and the errors the outlet receives go back to the client with the
	// address they came from.
	icmpMu sync.Mutex
	icmp   *icmpRelay

	// quote cache: the tun read loop keeps the header of recently sent UDP
	// packets so an ICMP error can quote the exact bytes the client sent.
	quoteMu sync.Mutex
	quotes  map[quoteKey]clientQuote

	// Hop views: a traceroute hop is handed to the client with a virtual
	// address of this range, and the reverse lookup of that address answers
	// with the real hop address. Views live for one traceroute round: the
	// probe TTL climbs inside a round and falls back when a new one starts,
	// which is when the previous round's views are dropped.
	hopMu     sync.Mutex
	hops      map[netip.Addr]hopView
	hopByReal map[netip.Addr]netip.Addr
	probeTTL  int
	probeAt   time.Time
	hopSuffix string
	// conn tracks the flows of the tun data path so replies can be mapped back
	// to the client.
	conn *conntrack
	// runtime is the in-memory mirror of the mapping table. It is restored at
	// startup from SQLite and, on the NAT path, reconciled against the nft map.
	runtime *runtimeMap

	// tunStack is the userspace stack that terminates the traffic arriving on
	// the device; tunCancel stops the device read/write loops on shutdown.
	tunStack   *tunStack
	tunCancel  context.CancelFunc
	tunMu      sync.Mutex // guards tunStarted
	tunStarted bool
}

func Init(bp *coremain.BP, args interface{}) (coremain.Plugin, error) {
	cfg := args.(*Args)

	if cfg.DBPath == "" {
		cfg.DBPath = "/etc/mosdns/fakeip.db"
	}
	if cfg.TablePrefix == "" {
		cfg.TablePrefix = "default"
	}
	if cfg.IPv4Range == "" {
		cfg.IPv4Range = "198.18.0.0/15"
	}
	if cfg.Script != "" {
		bp.L().Warn("script callback has been removed and is ignored; the plugin now manages nat itself or, with use_tun, routes to a tun device",
			zap.String("script", cfg.Script))
	}
	if cfg.TTL == 0 {
		cfg.TTL = 60
	}
	recordTTL, err := parseRecordTTL(cfg.RecordTTL)
	if err != nil {
		return nil, err
	}
	if cfg.RouteTable == "" {
		cfg.RouteTable = "main"
	}
	if !validRouteTable.MatchString(cfg.RouteTable) {
		return nil, fmt.Errorf("invalid route_table %q: only alphanumeric, underscore, dot and dash allowed", cfg.RouteTable)
	}
	if cfg.HopNameSuffix == "" {
		// Reuse the table prefix so a deployment names its hops after its
		// own table; underscores become dashes to keep the label legal.
		cfg.HopNameSuffix = strings.ReplaceAll(cfg.TablePrefix, "_", "-")
	}
	if !validHostLabel.MatchString(cfg.HopNameSuffix) {
		return nil, fmt.Errorf("invalid hop_name_suffix %q: only alphanumeric and dashes allowed", cfg.HopNameSuffix)
	}
	if cfg.TunRouteTable == "" {
		cfg.TunRouteTable = "100"
	}
	if !validRouteTable.MatchString(cfg.TunRouteTable) {
		return nil, fmt.Errorf("invalid tun_route_table %q: only alphanumeric, underscore, dot and dash allowed", cfg.TunRouteTable)
	}
	// route_aggregation defaults to true, so it is a pointer to tell "unset"
	// from an explicit false.
	aggregateRoutes := true
	if cfg.AggregateRoutes != nil {
		aggregateRoutes = *cfg.AggregateRoutes
	}

	bp.L().Debug("fakeip nat: config resolved",
		zap.String("db_path", cfg.DBPath),
		zap.String("table_prefix", cfg.TablePrefix),
		zap.String("ipv4_range", cfg.IPv4Range),
		zap.Uint32("ttl", cfg.TTL),
		zap.Duration("record_ttl", recordTTL),
		zap.String("route_table", cfg.RouteTable),
		zap.Bool("route_aggregation", aggregateRoutes),
		zap.Bool("use_tun", cfg.UseTun),
		zap.String("tun_dev", strings.TrimSpace(cfg.TunDev)),
		zap.String("next_hop", cfg.NextHop),
		zap.String("next_hop_dev", cfg.NextHopDev),
		zap.Bool("realip", cfg.RealIP),
		zap.Int("mss_clamp", cfg.MSSClamp),
		zap.Bool("proxy_configured", strings.TrimSpace(cfg.Proxy) != ""))

	if !validTableName.MatchString(cfg.TablePrefix) {
		return nil, fmt.Errorf("invalid table_prefix %q: only alphanumeric and underscore allowed", cfg.TablePrefix)
	}

	prefix, err := netip.ParsePrefix(cfg.IPv4Range)
	if err != nil {
		return nil, fmt.Errorf("invalid ipv4_range: %w", err)
	}
	// prefix.Addr().As4() panics on IPv6 inputs, so reject them at startup
	// instead of crashing on the first A query.
	if !prefix.Addr().Is4() {
		return nil, fmt.Errorf("invalid ipv4_range %q: must be an IPv4 prefix", cfg.IPv4Range)
	}
	ones, bits := prefix.Bits(), prefix.Addr().BitLen()
	if ones > bits-2 {
		return nil, fmt.Errorf("invalid ipv4_range %q: need at least 2 usable addresses", cfg.IPv4Range)
	}
	// Network and broadcast addresses are excluded.
	maxHosts := (uint64(1) << uint(bits-ones)) - 2

	if cfg.NextHop != "" {
		if _, err := netip.ParseAddr(cfg.NextHop); err != nil {
			return nil, fmt.Errorf("invalid next_hop IP %q: %w", cfg.NextHop, err)
		}
	}

	if cfg.MSSClamp != 0 && (cfg.MSSClamp < 536 || cfg.MSSClamp > 65535) {
		return nil, fmt.Errorf("invalid mss_clamp %d: must be 0 or between 536 and 65535", cfg.MSSClamp)
	}
	if cfg.MSSClamp > 0 && (cfg.UseTun || cfg.RealIP) {
		bp.L().Warn("mss_clamp only applies to the fake-ip nft table",
			zap.Int("mss_clamp", cfg.MSSClamp), zap.Bool("use_tun", cfg.UseTun), zap.Bool("realip", cfg.RealIP))
	}

	db, err := sql.Open("sqlite", cfg.DBPath+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
	if err != nil {
		return nil, fmt.Errorf("open sqlite failed: %w", err)
	}
	bp.L().Debug("fakeip nat: sqlite opened", zap.String("db_path", cfg.DBPath))
	// SQLite allows a single writer. Serializing at the pool level turns
	// concurrent writes into a Go-side queue instead of SQLITE_BUSY errors.
	db.SetMaxOpenConns(1)
	db.SetConnMaxIdleTime(time.Minute)

	mapTable := cfg.TablePrefix + "_mapping"
	ipTable := cfg.TablePrefix + "_real_ips"
	idxName := "idx_" + cfg.TablePrefix + "_real_ips_domain"

	initSQL := fmt.Sprintf(`
	CREATE TABLE IF NOT EXISTS %s (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		domain TEXT UNIQUE NOT NULL,
		fake_ip TEXT UNIQUE NOT NULL,
		created_at INTEGER DEFAULT 0,
		last_seen INTEGER DEFAULT 0
	);
	CREATE TABLE IF NOT EXISTS %s (
		domain TEXT NOT NULL,
		real_ip TEXT NOT NULL,
		last_seen INTEGER DEFAULT 0,
		PRIMARY KEY (domain, real_ip)
	);
	CREATE INDEX IF NOT EXISTS %s ON %s(domain);`,
		mapTable, ipTable, idxName, ipTable,
	)

	if _, err := db.Exec(initSQL); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("init tables failed: %w", err)
	}
	// Databases created before record_ttl was added have no last_seen column;
	// "duplicate column name" means the schema is already current.
	if _, err := db.Exec(fmt.Sprintf("ALTER TABLE %s ADD COLUMN last_seen INTEGER DEFAULT 0", mapTable)); err != nil {
		if !strings.Contains(err.Error(), "duplicate column name") {
			_ = db.Close()
			return nil, fmt.Errorf("add last_seen column failed: %w", err)
		}
	}
	bp.L().Debug("fakeip nat: schema ready",
		zap.String("map_table", mapTable), zap.String("real_ip_table", ipTable), zap.String("index", idxName))

	// Surface unusable paths (missing directory, bad permissions) at startup
	// instead of on the first query.
	pingCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.PingContext(pingCtx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite %q is not usable: %w", cfg.DBPath, err)
	}
	bp.L().Debug("fakeip nat: sqlite reachable", zap.String("db_path", cfg.DBPath))

	p := &FakeIPNatPlugin{
		BP:           bp,
		db:           db,
		dbPath:       cfg.DBPath,
		tablePrefix:  cfg.TablePrefix,
		mapTable:     mapTable,
		ipTable:      ipTable,
		cidr:         cfg.IPv4Range,
		prefix:       prefix,
		maxHosts:     maxHosts,
		ttl:          cfg.TTL,
		recordTTL:    recordTTL,
		nextHop:      strings.TrimSpace(cfg.NextHop),
		nextHopDev:   strings.TrimSpace(cfg.NextHopDev),
		realIP:       cfg.RealIP,
		realRoutes:   make(map[string]struct{}),
		taskSem:      make(chan struct{}, defaultTaskConcurrency),
		taskInFlight: make(map[string]struct{}),

		hopSuffix:       cfg.HopNameSuffix,
		routeTable:      cfg.RouteTable,
		tunRouteTable:   cfg.TunRouteTable,
		aggregateRoutes: aggregateRoutes,
		mssClamp:        cfg.MSSClamp,
		useTun:          cfg.UseTun,
		tunDev:          strings.TrimSpace(cfg.TunDev),
	}
	p.runner = execRunner{}
	p.probe = p.probeReachable
	p.egress = &directEgress{}
	p.conn = newConntrack(defaultConntrackSize, defaultConntrackTTL)
	p.runtime = newRuntimeMap()

	// Restore what earlier runs already mapped before any traffic arrives, so
	// the first query for a known domain is answered from memory.
	restoreCtx, restoreCancel := context.WithTimeout(context.Background(), 15*time.Second)
	if err := p.restoreRuntimeMappings(restoreCtx); err != nil {
		p.L().Warn("fakeip nat: restore runtime mappings failed", zap.Error(err))
	}
	// The nft path has a second source of truth: the dnat map survives restarts
	// even when a database row did not. Swap the differences into both. realip
	// mode has no DNAT map at all, so there is nothing to reconcile.
	if !p.useTun && !p.realIP {
		p.reconcileFirewallMappings(restoreCtx)
	}
	restoreCancel()

	// Stale mappings are dropped in the background, so a database that has been
	// growing for months does not need a manual vacuum.
	p.startRecordRetention()

	// The proxy is the outlet of the tun data path only: the NAT data path is
	// kernel DNAT and never sees the connection. An unusable proxy degrades to
	// direct egress instead of blocking startup, but it is logged as an error.
	if cfg.RealIP && cfg.UseTun {
		p.L().Warn("realip has no effect with use_tun: the tun data path routes the whole fake range instead of real IPs")
	}
	if cfg.Proxy != "" {
		dialer, err := newEgress(cfg.Proxy, cfg.ProxyInsecure)
		if err != nil {
			return nil, err
		}
		p.L().Debug("fakeip nat: proxy link parsed",
			zap.String("proxy", redactProxy(cfg.Proxy)),
			zap.String("outlet", describeEgress(dialer)),
			zap.Bool("insecure", cfg.ProxyInsecure))
		if !cfg.UseTun {
			p.L().Warn("proxy is configured but use_tun is false; it only applies to the tun data path",
				zap.String("proxy", redactProxy(cfg.Proxy)))
		} else {
			probeCtx, probeCancel := context.WithTimeout(context.Background(), 5*time.Second)
			p.L().Debug("fakeip nat: probing proxy egress", zap.String("proxy", redactProxy(cfg.Proxy)))
			if err := probeEgress(probeCtx, dialer); err != nil {
				p.L().Warn("proxy is not usable, falling back to direct egress",
					zap.String("proxy", redactProxy(cfg.Proxy)), zap.Error(err))
			} else {
				p.egress = dialer
				p.proxyActive = true
				p.L().Info("proxy egress ready", zap.String("proxy", redactProxy(cfg.Proxy)))
			}
			probeCancel()
		}
	}

	// The tun interface sits in front of the outlet, so its MTU bounds the
	// segment size the stack advertises to clients. A proxied outlet adds the
	// tunnel the proxy itself runs through, where Ethernet-size segments are
	// dropped, so the automatic choice is smaller there. An explicit tun_mtu
	// always wins.
	mtu, err := resolveTunMTU(cfg.TunMTU, p.proxyActive)
	if err != nil {
		return nil, err
	}
	p.tunMTU = mtu

	// The tun data path is the alternative to per-domain DNAT: it asks the
	// system for a device and routes the whole ipv4_range into it.
	if p.useTun {
		p.L().Debug("fakeip nat: starting tun data path", zap.String("range", p.cidr))
		if err := p.startTunDataPath(); err != nil {
			p.L().Error("use_tun is enabled but the tun data path could not start; the plugin has no outlet", zap.Error(err))
		} else {
			// The outlet is pinned only after the device exists: the range
			// address has to be assigned before it can be bound as a source.
			p.setupTunEgress()
		}
	}

	// The NAT data path writes one host route per resolution. A periodic scan
	// folds them into CIDR blocks; the tun path needs none of that.
	p.startRouteAggregation()

	// coremain never iterates plugins to close them, so the sqlite handle has
	// to ride on the shutdown channel that RunMosdns waits on.
	if m := bp.M(); m != nil {
		if sc := m.GetSafeClose(); sc != nil {
			sc.Attach(func(done func(), closeSignal <-chan struct{}) {
				defer done()
				<-closeSignal
				_ = p.Close()
			})
		}
	}

	plane := "nft"
	if p.useTun {
		plane = "tun"
	}
	p.L().Info("fakeip nat plugin initialized",
		zap.String("range", p.cidr),
		zap.Uint32("ttl", p.ttl),
		zap.String("data_plane", plane),
		zap.String("tun_dev", p.tunDev),
		zap.String("route_table", p.routeTable),
		zap.Bool("route_aggregation", p.aggregateRoutes),
		zap.Bool("proxy_active", p.proxyActive),
		zap.Uint32("tun_mtu", p.tunMTU))

	return p, nil
}

// startTunDataPath brings up the userspace stack and the device loops. It runs
// as a goroutine because the socket layer must never block Init: coremain only
// waits for Init, and a failure here is degraded, not fatal.
func (p *FakeIPNatPlugin) startTunDataPath() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	dev, err := p.setupTun(ctx)
	if err != nil {
		return err
	}
	st, err := newTunStack(p.tunMTU, p.reservedAddr())
	if err != nil {
		_ = dev.Close()
		return err
	}
	st.dev = dev
	p.L().Debug("fakeip nat: userspace stack created",
		zap.Uint32("mtu", st.mtu), zap.Int("nic_id", int(st.nicID)))
	p.startStack(st)

	runCtx, runCancel := context.WithCancel(context.Background())
	p.tunMu.Lock()
	p.tunStack = st
	p.tunCancel = runCancel
	p.tunStarted = true
	p.tunMu.Unlock()

	devName := p.tunDev
	p.L().Info("tun data path started", zap.String("dev", devName), zap.String("range", p.cidr))
	// ICMP relay needs the device for replies and the mapping table for echo
	// forwarding, so it starts once both exist.
	p.startICMPRelay(runCtx, st)
	go func() {
		if err := p.runTunDevice(runCtx, dev, st); err != nil {
			p.L().Warn("tun device loop stopped", zap.String("dev", devName), zap.Error(err))
		}
	}()
	return nil
}

// stopTunDataPath stops the device loops and the stack. It is idempotent.
func (p *FakeIPNatPlugin) stopTunDataPath() {
	p.tunMu.Lock()
	cancel := p.tunCancel
	st := p.tunStack
	started := p.tunStarted
	p.tunStarted = false
	p.tunCancel = nil
	p.tunStack = nil
	p.tunMu.Unlock()

	if !started {
		p.L().Debug("fakeip nat: tun data path not running, nothing to stop")
		return
	}
	p.L().Debug("fakeip nat: stopping tun data path", zap.String("dev", p.tunDev))
	p.stopICMPRelay()
	if cancel != nil {
		cancel()
	}
	if st != nil {
		st.close()
	}
}

// startRouteAggregation runs the managed-route collapse on a timer. The scan
// reads the routing table, not a memory set, so host routes written by an
// earlier process are collapsed too. Only the NAT data path needs it: the tun
// data path routes the whole fake range as one prefix already.
func (p *FakeIPNatPlugin) startRouteAggregation() {
	if p.useTun || !p.aggregateRoutes {
		return
	}
	p.aggMu.Lock()
	if p.aggStop != nil {
		p.aggMu.Unlock()
		return
	}
	stop := make(chan struct{})
	done := make(chan struct{})
	p.aggStop, p.aggDone = stop, done
	p.aggMu.Unlock()

	go func() {
		defer close(done)
		ticker := time.NewTicker(routeAggInterval)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				p.aggregateManagedRoutes()
			}
		}
	}()
	p.L().Debug("fakeip nat: route aggregation started", zap.Duration("interval", routeAggInterval))
}

// stopRouteAggregation stops the loop and waits for a running collapse to
// finish, so no ip command outlives the plugin.
func (p *FakeIPNatPlugin) stopRouteAggregation() {
	p.aggMu.Lock()
	stop, done := p.aggStop, p.aggDone
	p.aggStop, p.aggDone = nil, nil
	p.aggMu.Unlock()
	if stop == nil {
		return
	}
	close(stop)
	<-done
}

// Close stops the data path and releases the SQLite handle. Without it the
// database file stays locked for the lifetime of the process.
func (p *FakeIPNatPlugin) Close() error {
	p.L().Debug("fakeip nat: closing plugin")
	p.stopRouteAggregation()
	p.cleanupDataPath()
	p.stopRecordRetention()
	p.stopTunDataPath()
	p.stopTunEgress()
	if p.db != nil {
		if err := p.db.Close(); err != nil {
			p.L().Warn("fakeip nat: close sqlite failed", zap.String("db_path", p.dbPath), zap.Error(err))
			return err
		}
		p.L().Info("fakeip nat plugin closed")
	}
	return nil
}

func (p *FakeIPNatPlugin) Exec(ctx context.Context, qCtx *query_context.Context, next executable_seq.ExecutableChainNode) error {
	q := qCtx.Q()
	if len(q.Question) == 0 {
		return executable_seq.ExecChainNode(ctx, qCtx, next)
	}

	question := q.Question[0]
	// A traceroute hop is shown to the client as a virtual address of this
	// range; its reverse lookup names the real hop, so the client prints
	// "<real hop> (<virtual ip>)" instead of a bare address.
	if question.Qtype == dns.TypePTR {
		if addr, ok := ptrAddr(question.Name); ok {
			if real, ok := p.hopOf(addr); ok {
				resp := new(dns.Msg)
				resp.SetReply(q)
				resp.RecursionAvailable = true
				resp.Answer = []dns.RR{&dns.PTR{
					Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: uint32(hopViewTTL.Seconds())},
					// A dotted quad on its own is not a valid host name, so
					// the resolver would throw the answer away and traceroute
					// would print the bare address. The suffix makes it a
					// domain while keeping the address readable as-is.
					Ptr: real.String() + "." + p.hopSuffix + ".",
				}}
				p.L().Debug("fakeip nat: hop reverse lookup answered",
					zap.String("name", question.Name), zap.String("virtual_ip", addr.String()), zap.String("real_ip", real.String()))
				qCtx.SetResponse(resp)
				return nil
			}
		}
	}
	p.L().Debug("fakeip nat: query in",
		zap.String("name", question.Name), zap.Uint16("qtype", question.Qtype),
		zap.Bool("has_response", qCtx.R() != nil))
	if question.Qtype == dns.TypeAAAA {
		p.L().Debug("fakeip nat: aaaa answered with empty response", zap.String("name", question.Name))
		emptyResp := new(dns.Msg)
		emptyResp.SetReply(q)
		emptyResp.RecursionAvailable = true
		qCtx.SetResponse(emptyResp)
		return nil
	}

	alreadyResolved := (qCtx.R() != nil)
	if !alreadyResolved {
		if err := executable_seq.ExecChainNode(ctx, qCtx, next); err != nil {
			return err
		}
	} else {
		p.L().Debug("fakeip nat: response already present, skip next", zap.String("name", question.Name))
	}

	resp := qCtx.R()
	if resp != nil && question.Qtype == dns.TypeA {
		var realIPs []string
		for _, ans := range resp.Answer {
			if aRecord, ok := ans.(*dns.A); ok {
				realIPs = append(realIPs, aRecord.A.String())
			}
		}

		if len(realIPs) > 0 {
			domain := strings.TrimSuffix(question.Name, ".")
			p.L().Debug("fakeip nat: real ips collected",
				zap.String("domain", domain), zap.Int("count", len(realIPs)), zap.Strings("real_ips", realIPs))
			if p.realIP {
				// Pure routing mode: the answer keeps the real IPs and the
				// plugin only steers each of them out of the chosen gateway.
				p.L().Debug("fakeip nat: realip mode keeps real answers",
					zap.String("domain", domain), zap.Strings("real_ips", realIPs))
				go p.syncRealRoutes(context.Background(), realIPs)
			} else {
				fakeIP, err := p.recordAndAllocate(ctx, domain, realIPs)
				if err != nil {
					p.L().Error("sqlite record fakeip failed", zap.String("domain", domain), zap.Error(err))
				} else if fakeAddr, err := netip.ParseAddr(fakeIP); err != nil {
					// A leftover "pending" row or a corrupted value must never
					// produce an A record with a nil IP.
					p.L().Error("invalid allocated fake ip", zap.String("domain", domain), zap.String("fake_ip", fakeIP), zap.Error(err))
				} else {
					// Wait for the data plane before answering: a client that
					// receives a fake IP while the DNAT entry is still missing
					// can only fail, which is what "the mapping exists but the
					// client got a real IP" looked like from the outside.
					ready := p.dispatchNAT(ctx, fakeIP, domain, strings.Join(realIPs, ","))
					if !ready {
						p.L().Warn("nat mapping not ready, answering fake ip anyway",
							zap.String("domain", domain), zap.String("fake_ip", fakeIP))
					}
					p.L().Debug("fakeip nat: fake ip answered",
						zap.String("domain", domain), zap.String("fake_ip", fakeIP),
						zap.Uint32("ttl", p.ttl), zap.Bool("data_plane_tun", p.useTun))

					newResp := new(dns.Msg)
					newResp.SetReply(q)
					newResp.RecursionAvailable = true
					newResp.Answer = []dns.RR{
						&dns.A{
							Hdr: dns.RR_Header{
								Name:   question.Name,
								Rrtype: dns.TypeA,
								Class:  dns.ClassINET,
								Ttl:    p.ttl,
							},
							A: fakeAddr.AsSlice(),
						},
					}
					qCtx.SetResponse(newResp)
				}
			}
		}
	}

	if alreadyResolved {
		return executable_seq.ExecChainNode(ctx, qCtx, next)
	}
	return nil
}

// recordAndAllocate returns a stable fake ip for domain and records the
// currently resolved real ips. It is idempotent across processes: concurrent
// instances race on INSERT ... ON CONFLICT DO NOTHING instead of UNIQUE errors.
func (p *FakeIPNatPlugin) recordAndAllocate(ctx context.Context, domain string, realIPs []string) (string, error) {
	now := time.Now().Unix()

	// Real ips are idempotent upserts, so they do not need the allocation lock.
	if err := p.upsertRealIPs(ctx, domain, realIPs, now); err != nil {
		p.L().Warn("upsert real ips failed", zap.String("domain", domain), zap.Int("ip_count", len(realIPs)), zap.Error(err))
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	insertSQL := fmt.Sprintf("INSERT INTO %s (domain, fake_ip, created_at, last_seen) VALUES (?, ?, ?, ?) ON CONFLICT(domain) DO NOTHING", p.mapTable)
	if _, err := p.db.ExecContext(ctx, insertSQL, domain, pendingFakeIP, now, now); err != nil {
		return "", fmt.Errorf("insert mapping: %w", err)
	}

	var (
		id     int64
		fakeIP string
	)
	querySQL := fmt.Sprintf("SELECT id, fake_ip FROM %s WHERE domain = ?", p.mapTable)
	if err := p.db.QueryRowContext(ctx, querySQL, domain).Scan(&id, &fakeIP); err != nil {
		return "", fmt.Errorf("query mapping: %w", err)
	}
	if fakeIP != pendingFakeIP {
		// Keep the runtime table in step with what was just allocated.
		if p.runtime != nil {
			p.runtime.put(domain, fakeIP)
			p.runtime.touch(domain, now)
		}
		return fakeIP, nil
	}

	// The row exists but has no address yet. Take the lowest free offset instead
	// of deriving one from the row id: ids never shrink, so an id-based offset
	// would keep walking towards the end of the range even after the retention
	// sweep has freed addresses behind it.
	updateSQL := fmt.Sprintf("UPDATE %s SET fake_ip = ?, last_seen = ? WHERE id = ? AND fake_ip = ?", p.mapTable)
	skip := make(map[string]bool)
	for attempt := 0; attempt < 16; attempt++ {
		allocated, err := p.nextFreeFakeIP(skip)
		if err != nil {
			return "", err
		}
		res, err := p.db.ExecContext(ctx, updateSQL, allocated, now, id, pendingFakeIP)
		if err != nil {
			// Another process took this offset between the scan and the write.
			if isUniqueViolation(err) {
				skip[allocated] = true
				continue
			}
			return "", fmt.Errorf("update mapping: %w", err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			// Another process flipped this row first; its address wins.
			if err := p.db.QueryRowContext(ctx, querySQL, domain).Scan(&id, &fakeIP); err != nil {
				return "", fmt.Errorf("query mapping: %w", err)
			}
			if fakeIP != pendingFakeIP {
				if p.runtime != nil {
					p.runtime.put(domain, fakeIP)
					p.runtime.touch(domain, now)
				}
				return fakeIP, nil
			}
			continue
		}
		if p.runtime != nil {
			p.runtime.put(domain, allocated)
			p.runtime.touch(domain, now)
		}
		p.L().Debug("fakeip nat: address allocated",
			zap.String("domain", domain), zap.String("fake_ip", allocated), zap.Int64("row_id", id))
		return allocated, nil
	}
	return "", fmt.Errorf("fake ip for %q could not be allocated after retries", domain)
}

// nextFreeFakeIP returns the lowest offset that is neither held by the runtime
// table, a firewall reservation, nor a live traceroute hop. skip carries
// addresses another process won while this allocation was retrying.
func (p *FakeIPNatPlugin) nextFreeFakeIP(skip map[string]bool) (string, error) {
	usable := p.maxHosts - reservedHostOffset
	if p.maxHosts <= reservedHostOffset {
		return "", fmt.Errorf("ipv4_range %s has no allocatable address: first host is reserved for the tun device", p.cidr)
	}
	base := p.prefix.Addr().As4()
	baseUint := uint64(binary.BigEndian.Uint32(base[:]))

	p.hopMu.Lock()
	defer p.hopMu.Unlock()
	for i := uint64(0); i < usable; i++ {
		offset := i + reservedHostOffset + 1
		target := baseUint + offset
		if target > 0xFFFFFFFF {
			break
		}
		var a [4]byte
		binary.BigEndian.PutUint32(a[:], uint32(target))
		addr := netip.AddrFrom4(a)
		s := addr.String()
		if skip[s] || p.runtime.taken(s) {
			continue
		}
		if v, ok := p.hops[addr]; ok && time.Since(v.at) <= hopViewTTL {
			continue
		}
		return s, nil
	}
	return "", fmt.Errorf("no free fake ip left in %s (%d allocatable addresses in use)", p.cidr, usable)
}

// isUniqueViolation reports whether SQLite refused a write because an address
// was taken by another process between the scan and the update.
func isUniqueViolation(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}

// allocateFakeIP maps a monotonic row id into the configured prefix. The first
// host of the range is owned by the tun device (see reservedFakeIP), so
// allocation starts after it and hands out only the remaining addresses.
func (p *FakeIPNatPlugin) allocateFakeIP(id uint64) (string, error) {
	if id == 0 {
		id = 1
	}
	usable := p.maxHosts - reservedHostOffset
	if p.maxHosts <= reservedHostOffset {
		return "", fmt.Errorf("ipv4_range %s has no allocatable address: first host is reserved for the tun device", p.cidr)
	}
	base := p.prefix.Addr().As4()
	baseUint := uint64(binary.BigEndian.Uint32(base[:]))
	offset := (id-1)%usable + reservedHostOffset + 1
	targetUint := baseUint + offset
	if targetUint > 0xFFFFFFFF {
		return "", fmt.Errorf("allocated address out of range for %s (row id %d)", p.cidr, id)
	}
	var a [4]byte
	binary.BigEndian.PutUint32(a[:], uint32(targetUint))
	addr := netip.AddrFrom4(a)
	p.L().Debug("fakeip nat: address allocated",
		zap.Uint64("row_id", id), zap.Uint64("offset", offset), zap.String("fake_ip", addr.String()))
	return addr.String(), nil
}

// upsertRealIPs stores all real ips of domain in one round trip.
func (p *FakeIPNatPlugin) upsertRealIPs(ctx context.Context, domain string, realIPs []string, now int64) error {
	var b strings.Builder
	b.WriteString("INSERT INTO ")
	b.WriteString(p.ipTable)
	b.WriteString(" (domain, real_ip, last_seen) VALUES ")

	args := make([]interface{}, 0, len(realIPs)*3)
	seen := make(map[string]struct{}, len(realIPs))
	n := 0
	for _, ip := range realIPs {
		if _, ok := seen[ip]; ok {
			continue
		}
		seen[ip] = struct{}{}
		if n > 0 {
			b.WriteString(",")
		}
		b.WriteString("(?,?,?)")
		args = append(args, domain, ip, now)
		n++
	}
	if n == 0 {
		return nil
	}
	b.WriteString(" ON CONFLICT(domain, real_ip) DO UPDATE SET last_seen = excluded.last_seen")
	_, err := p.db.ExecContext(ctx, b.String(), args...)
	return err
}

// dispatchNAT maps one fake ip to a real ip and reports whether the data plane
// is ready for it. The NAT path must have the DNAT entry in place before the
// fake IP reaches the client, so the query waits for the task (bounded by
// natSyncWait) instead of racing it. The tun path routes the whole range, so
// there is nothing per-domain to do and it is always ready.
func (p *FakeIPNatPlugin) dispatchNAT(ctx context.Context, fakeIP, domain, latestIPs string) bool {
	if p.useTun {
		p.L().Debug("fakeip nat: nat dispatch skipped, tun data plane owns the range",
			zap.String("domain", domain), zap.String("fake_ip", fakeIP))
		return true
	}
	done := make(chan bool, 1)
	if !p.enqueueTask(domain, func() {
		done <- p.syncNAT(context.Background(), fakeIP, domain, latestIPs)
	}) {
		return false
	}
	select {
	case ok := <-done:
		return ok
	case <-ctx.Done():
		p.L().Debug("nat dispatch wait interrupted", zap.String("domain", domain), zap.Error(ctx.Err()))
		return false
	case <-time.After(natSyncWait):
		p.L().Warn("nat mapping is still running, answering without waiting",
			zap.String("domain", domain), zap.String("fake_ip", fakeIP))
		return false
	}
}

// enqueueTask runs fn in the background: at most one task per domain and at
// most defaultTaskConcurrency tasks overall. It reports whether the task was
// actually started.
func (p *FakeIPNatPlugin) enqueueTask(domain string, fn func()) bool {
	p.taskMu.Lock()
	if _, ok := p.taskInFlight[domain]; ok {
		p.taskMu.Unlock()
		p.L().Debug("nat task already running for domain", zap.String("domain", domain))
		return false
	}
	select {
	case p.taskSem <- struct{}{}:
		p.taskInFlight[domain] = struct{}{}
		p.taskMu.Unlock()
	default:
		p.taskMu.Unlock()
		p.L().Warn("nat task concurrency limit reached, skip", zap.String("domain", domain), zap.Int("limit", cap(p.taskSem)))
		return false
	}

	go func() {
		defer func() {
			<-p.taskSem
			p.taskMu.Lock()
			delete(p.taskInFlight, domain)
			p.taskMu.Unlock()
		}()
		fn()
	}()
	return true
}
