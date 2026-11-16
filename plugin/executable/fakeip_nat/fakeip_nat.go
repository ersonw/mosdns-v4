package fakeipnat

import (
	"context"
	"database/sql"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/ersonw/mosdns-v4/coremain"
	"github.com/ersonw/mosdns-v4/pkg/egress"
	"github.com/ersonw/mosdns-v4/pkg/executable_seq"
	"github.com/ersonw/mosdns-v4/pkg/query_context"
	"github.com/ersonw/mosdns-v4/pkg/routepolicy"
	"github.com/ersonw/mosdns-v4/pkg/timeutil"
	"github.com/miekg/dns"
	"go.uber.org/zap"
	_ "modernc.org/sqlite"
)

const PluginType = "fakeip_nat"

// pendingFakeIP marks a mapping row that has an id but no allocated address yet.
// It is only visible between the INSERT and the UPDATE inside recordAndAllocate,
// or after a crash in that window.
//
// The placeholder is per-domain: fake_ip is globally UNIQUE, so a single shared
// "pending" value would make every new domain collide with the row a crash left
// behind. The bare "pending" form is kept for databases written before this fix.
const pendingFakeIP = "pending"
const pendingFakeIPPrefix = pendingFakeIP + ":"

func pendingFakeIPFor(domain string) string { return pendingFakeIPPrefix + domain }

func isPendingFakeIP(fakeIP string) bool {
	return fakeIP == pendingFakeIP || strings.HasPrefix(fakeIP, pendingFakeIPPrefix)
}

// defaultTaskConcurrency caps how many NAT tasks run at the same time.
const defaultTaskConcurrency = 8

// realIPWriteInterval throttles the durable copy of a domain's real ips. The
// database is the restart fallback, not the read path: the memory table answers
// lookups, and syncNAT gets the freshest candidates from the answer itself. One
// row write per answer per domain was pure overhead on a busy resolver.
const realIPWriteInterval = 5 * time.Minute

var validTableName = regexp.MustCompile(`^[a-zA-Z0-9_]+$`)

// route tables are either a name (main, oversea) or an iproute2 id.
var validRouteTable = regexp.MustCompile(`^[a-zA-Z0-9_.-]+$`)

// defaultRouteRulePriority is the ip rule priority used when the config leaves
// it empty. A value equal to this default is treated as "not declared", which
// is what lets an inherited exit decision replace it without a spurious
// duplicate warning.
const defaultRouteRulePriority = 1000

// validHostLabel keeps hop_name_suffix a single DNS label.
var validHostLabel = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() interface{} { return new(Args) })
}

type Args struct {
	DBPath      string `yaml:"db_path"`      // SQLite 路径，默认: "/config/mosdns/fakeip.db"
	TablePrefix string `yaml:"table_prefix"` // 数据库表名前缀，默认: "default"
	// Timezone controls how stored Unix timestamps are rendered by the admin
	// surface. Default "Asia/Shanghai"; SQLite keeps seconds since the epoch.
	Timezone  string `yaml:"timezone"`
	IPv4Range string `yaml:"ipv4_range"` // 虚拟 IP 段，默认: "198.18.0.0/15"
	TTL       uint32 `yaml:"ttl"`        // 返回的 DNS TTL，默认: 60
	// RecordTTL 是域名映射的保留时长，默认 "168h"（7 天）。超过该时长没有被查询过的
	// 记录会被后台任务从 SQLite 和内存中删除，释放的虚拟地址重新进入可分配池。
	// 填 "0" 关闭清理（记录一直保留）。支持 Go 时长语法：168h、24h、30m。
	RecordTTL string `yaml:"record_ttl"`

	// AccessLog 记录每个源 IP 访问了哪些域名，默认 true。记录写入同一份
	// SQLite（<table_prefix>_access），供管理端按客户端 IP 导出访问记录。
	AccessLog *bool `yaml:"access_log"`
	// AccessTTL 是访问记录的保留时长，默认 "168h"（7 天）；"0" 表示不自动清理。
	AccessTTL  string `yaml:"access_ttl"`
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

	// RouteMark 打开「目的地址打标」分流：映射出来的真实 IP 只进 nft 集合
	// real_ipv4，由 prerouting / output 两个钩子给目的地址打上这个 mark，再用
	// 一条 ip rule fwmark 把这些包导进 RouteTable 里的专用表（表内只有一条指向
	// next_hop / next_hop_dev 的 default）。0 表示关闭（默认，仍写 /32 host route）。
	// 与 use_tun 互斥，且只在 Linux 上可用；route_table 不能是 main——打标的意义
	// 就是别再往主表里堆东西。取值要避开本机已有用途（例如 gost 的 -M、wg 的
	// fwmark 已占用的位）。
	RouteMark uint32 `yaml:"route_mark"`
	// RouteRulePriority 是那条 ip rule 的优先级，默认 1000。数值越小越先匹配，
	// 与既有策略规则冲突时调大它，让本插件的规则排在后面。
	RouteRulePriority int `yaml:"route_rule_priority"`

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
	// Egress 借用另一个插件声明的出口（一般是 egress_route 的 tag），用来代替
	// 这里的 proxy / proxy_insecure。出口的 mark、路由表和代理都在那个插件里
	// 维护，本插件只拿它的拨号器，所以同一个出口可以被多个数据面共用、统一
	// 巡检和回滚。
	// 与 proxy 互斥；被借用的插件必须在配置里排在它前面，否则启动时找不到。
	Egress string `yaml:"egress"`

	// IPv6Egress 控制直连 tun 出口的 IPv6 能力探测，默认 "auto"：
	// auto：启动时拨一次 ipv6_probe，之后按 ipv6_probe_interval 复查。拨通才给
	// 纯 IPv6 域名（A 为空、只有 AAAA）分配虚拟 IPv4，让客户端用假 IPv4 进来、
	// 插件再直连真实 IPv6 地址出去；拨不通则维持原行为，A 仍是空应答。
	// off：关闭探测，纯 IPv6 域名一律不分配虚拟 IP。
	// 只在 use_tun 且 realip=false 时生效；配了可用 proxy 时仍按代理路径处理。
	IPv6Egress string `yaml:"ipv6_egress"`
	// IPv6Probe 是探测目标（host:port），默认 "[2606:4700:4700::1111]:443"。
	// 用地址字面量，避免探测本身依赖本插件的 DNS 答复。
	IPv6Probe string `yaml:"ipv6_probe"`
	// IPv6ProbeInterval 是重复探测间隔，默认 "5m"；"0" 表示只在启动时探测一次。
	// 链路（NAT66 / NPTv6）后来才打通时靠它自动接上，不必重启。
	IPv6ProbeInterval string `yaml:"ipv6_probe_interval"`

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

	// CaptureCIDRs 是除虚拟地址段之外、本插件也要承载的真实目的地址前缀。
	// 自带地址表的 App（TikTok 这类）从不走解析，连接直接落在虚拟段外，如果
	// 不接管就会由主机自己拨号，在受限网络里表现为握手出去、回包全无。
	// 这里列出的前缀会被路由进 tun 设备，并在读取循环里被接受，然后和其它
	// 流量一样经由出口转发。仅在 use_tun 下生效。
	CaptureCIDRs []string `yaml:"capture_cidrs"`
	// CaptureFile 与 CaptureCIDRs 作用相同，但前缀从一个文本文件读取：每行
	// 一个 CIDR，# 开头的行忽略。便于不改配置就扩充列表。
	CaptureFile string `yaml:"capture_file"`
}

type FakeIPNatPlugin struct {
	*coremain.BP
	db          *sql.DB
	dbPath      string
	tablePrefix string
	mapTable    string
	ipTable     string
	// routesTable is the durable ledger of the prefixes this plugin installed.
	// A route written by a stopped process is removed again from that record,
	// not from a scan filtered by hop/device, so cleanup survives a crash and a
	// configuration change.
	routesTable string
	cidr        string
	prefix      netip.Prefix
	maxHosts    uint64 // usable address count inside prefix, broadcast and network excluded
	ttl         uint32
	recordTTL   time.Duration
	// accessLog / accessTTL / accessTable back the per-client visit log.
	accessLog     bool
	accessTTL     time.Duration
	accessTable   string
	retentionStop chan struct{}
	retentionOnce sync.Once
	// accessBuf batches the per-client rows so the answer path never writes
	// SQLite: a router answers hundreds of queries per second and every upsert
	// was a separate serialized round trip on the single connection.
	accessMu        sync.Mutex
	accessBuf       map[accessKey]accessRow
	accessFlushStop chan struct{}
	accessFlushDone chan struct{}
	nextHop         string
	nextHopDev      string
	// realIP mirrors Args.RealIP: when set the plugin answers real IPs and only
	// maintains the host routes that steer them out of the chosen gateway.
	realIP  bool
	timeLoc *time.Location
	mu      sync.Mutex // serializes fake ip allocation

	taskSem      chan struct{}       // bounds concurrently running NAT tasks
	taskMu       sync.Mutex          // guards taskInFlight
	taskInFlight map[string]struct{} // domains whose NAT task is running

	// NAT data path: the plugin owns the nftables map and host routes.
	routeTable      string
	aggregateRoutes bool
	// routeMark turns the host-route-per-address shape into destination marking:
	// the mapped addresses live in an nft set, and a policy rule sends the marked
	// packets into routeTable, which holds one default route.
	routeMark         uint32
	routeRulePriority int
	// markMu guards markReady and markActive. markReady means the nft set and the
	// two mark chains exist; markActive means the default route and the ip rule
	// are installed as well, so an address can simply be added to the set.
	markMu     sync.Mutex
	markReady  bool
	markActive bool
	// borrowed is the exit named by egress. It carries the decision the exit
	// installed and, when the exit owns a destination set, the registrar the
	// non-tun path hands its mapped addresses to.
	borrowed *borrowedExit
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
	// ledger keeps every installed prefix in memory and writes it behind, so an
	// answer never waits on SQLite for a route it just installed.
	ledger   *routeLedger
	ledgerMu sync.Mutex
	// stateTable records what the previous run installed on the system (the
	// route_mark path), so the next run can undo exactly that after a crash, a
	// mode switch or a configuration change.
	stateTable string
	// startupTasks is the queue of cleanup work that must not hold Init (see
	// startup_queue.go); startupWG lets Close wait for the drain to finish
	// before it removes the routes this run owns.
	startupMu    sync.Mutex
	startupTasks []startupTask
	startupWG    sync.WaitGroup
	// maintMu guards the maintenance loop: it flushes the ledger and re-resolves
	// the system default route, none of which belongs on the answer path.
	maintMu   sync.Mutex
	maintStop chan struct{}
	maintDone chan struct{}
	// sysHop / sysDev cache the system default route for the same reason: a
	// shell call per answer is what made the fallback look slow.
	sysMu    sync.Mutex
	sysHop   string
	sysDev   string
	sysValid bool
	natMu    sync.Mutex // serializes nft / ip command sequences
	runner   cmdRunner
	probe    func(ctx context.Context, ip string) bool
	// nftMirror is the in-memory copy of the DNAT map (fake ip -> real ip).
	// The plugin writes every element itself, so reading the kernel map is
	// only needed at startup; the answer path must not pay a dump per domain.
	nftMu       sync.Mutex
	nftMirror   map[string]string
	nftLoaded   bool // a full read happened; the mirror is authoritative
	nftVerified bool // the table was validated for this run
	// ownedCache memoizes the set of prefixes the ledger owns, for one ledger
	// version (see ownedPrefixSet).
	ownedMu       sync.Mutex
	ownedCache    map[string]struct{}
	ownedCacheVer uint64

	// Traffic watch: the tun reader feeds trafficWatch directly; the non-tun
	// fakeip path polls conntrack because the kernel DNAT never exposes the
	// packets to Go. Both paths share the same per-source ring.
	watch            *trafficWatch
	watchNames       *watchNameCache
	watchMu          sync.Mutex
	watchCtx         context.Context
	watchCancel      context.CancelFunc
	conntrackCancels map[string]context.CancelFunc
	watchWG          sync.WaitGroup

	// TUN data path: the whole ipv4_range is routed to a device requested from
	// the system instead of being DNAT-ed hop by hop.
	useTun bool
	tunDev string
	// capturePrefixes are real destinations the device carries in addition to
	// the fake range. An app that ships its own address list never asks the
	// resolver, so its connections land outside the fake range and would be
	// dialed straight from the host, where they are blocked or unreachable.
	// Each prefix is routed into the device and accepted by the device read
	// loop, then relayed through the outlet like any other flow.
	capturePrefixes []netip.Prefix
	// tunMTU is the MTU written to the device and advertised by the stack. It
	// is resolved once in Init from tun_mtu, or from the outlet kind.
	tunMTU uint32
	// egress is the outlet of the tun data path: direct by default, or a
	// socks5 / http / trojan proxy when `proxy` is configured and reachable.
	egress egressDialer
	// proxyActive reports whether egress is a proxied outlet. It decides the
	// target handed to it (the domain when proxied, the real IP when direct),
	// whether the tun SNAT table is installed, and how an echo request is
	// answered: a proxy cannot carry ICMP, so a proxied outlet answers it
	// locally and a direct one forwards it to the real host.
	proxyActive bool
	// v6egress answers whether a direct outlet can reach an IPv6 destination.
	// Nil means probing is off, and then an IPv6-only name keeps getting the
	// empty answer it always got.
	v6egress *v6EgressProbe

	// Tun outlet routing: a dedicated table keeps the fake range out of the
	// host default route, so only the new sockets opened for a flow leave
	// through next_hop, and the host's own traffic is untouched.
	tunRouteTable    string
	tunEgressHop     string
	tunEgressDev     string
	tunEgressCleanup func()
	// tunFakeRuleCleanup removes the rule that pins the fake range to main.
	tunFakeRuleCleanup func()
	// captureRuleCleanup removes the rules that pin capture prefixes to main.
	captureRuleCleanup func()
	// policyRuleSupported mirrors supportsNamedRouteTable(): only a platform with
	// named routing tables and ip rule can pin the fake range ahead of the host
	// policy routing.
	policyRuleSupported bool

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

	// realDest is the set of real destinations this run routed into the device
	// on purpose (their mark put them there). The device read loop accepts a
	// destination only when it is in this set, so a packet another route pushed
	// into the device is dropped instead of being dialled out.
	realDestMu sync.Mutex
	realDest   map[string]int64

	// tunStack is the userspace stack that terminates the traffic arriving on
	// the device; tunCancel stops the device read/write loops on shutdown.
	tunStack   *tunStack
	tunCancel  context.CancelFunc
	tunMu      sync.Mutex // guards tunStarted
	tunStarted bool
}

// Location is the timezone used to render this plugin's stored timestamps.
func (p *FakeIPNatPlugin) Location() *time.Location {
	if p.timeLoc == nil {
		return timeutil.MustDefault()
	}
	return p.timeLoc
}

func Init(bp *coremain.BP, args interface{}) (coremain.Plugin, error) {
	initStarted := time.Now()
	cfg := args.(*Args)

	tzLoc, tzErr := timeutil.Load(cfg.Timezone)
	if tzErr != nil {
		return nil, tzErr
	}
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
	accessLog := true
	if cfg.AccessLog != nil {
		accessLog = *cfg.AccessLog
	}
	accessTTL, err := parseAccessTTL(cfg.AccessTTL)
	if err != nil {
		return nil, err
	}
	if cfg.RouteTable == "" {
		cfg.RouteTable = "main"
	}
	if !validRouteTable.MatchString(cfg.RouteTable) {
		return nil, fmt.Errorf("invalid route_table %q: only alphanumeric, underscore, dot and dash allowed", cfg.RouteTable)
	}
	// BSD/macOS and Windows expose a single routing table, so a named table
	// falls back to the main one instead of silently failing every write.
	if cfg.RouteTable != "main" && !supportsNamedRouteTable() {
		bp.L().Warn("route_table is only supported on linux, falling back to the main table",
			zap.String("route_table", cfg.RouteTable))
		cfg.RouteTable = "main"
	}
	routeRulePriority := cfg.RouteRulePriority
	if routeRulePriority == 0 {
		routeRulePriority = defaultRouteRulePriority
	}
	if err := validateRouteMark(cfg, routeRulePriority); err != nil {
		return nil, err
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
		zap.Uint32("route_mark", cfg.RouteMark),
		zap.Int("route_rule_priority", routeRulePriority),
		zap.Bool("use_tun", cfg.UseTun),
		zap.String("tun_dev", strings.TrimSpace(cfg.TunDev)),
		zap.String("next_hop", cfg.NextHop),
		zap.String("next_hop_dev", cfg.NextHopDev),
		zap.Bool("realip", cfg.RealIP),
		zap.Int("mss_clamp", cfg.MSSClamp),
		zap.Bool("proxy_configured", strings.TrimSpace(cfg.Proxy) != ""),
		zap.String("ipv6_egress", strings.TrimSpace(cfg.IPv6Egress)),
		zap.String("ipv6_probe", strings.TrimSpace(cfg.IPv6Probe)))

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

	capturePrefixes, err := loadCapturePrefixes(cfg.CaptureCIDRs, cfg.CaptureFile)
	if err != nil {
		return nil, err
	}

	// IPv6 egress detection: a direct outlet can only answer a fake IPv4 for an
	// IPv6-only name when the host itself can reach IPv6. The probe target and
	// the mode are fixed at startup; only the result is refreshed.
	switch strings.ToLower(strings.TrimSpace(cfg.IPv6Egress)) {
	case "", "auto", "off", "disable", "disabled":
	default:
		return nil, fmt.Errorf("invalid ipv6_egress %q: must be auto or off", cfg.IPv6Egress)
	}
	ipv6ProbeInterval, err := parseIPv6ProbeInterval(cfg.IPv6ProbeInterval)
	if err != nil {
		return nil, err
	}
	if cfg.IPv6Probe != "" {
		if _, _, splitErr := net.SplitHostPort(cfg.IPv6Probe); splitErr != nil {
			return nil, fmt.Errorf("invalid ipv6_probe %q: want host:port, e.g. [2606:4700:4700::1111]:443", cfg.IPv6Probe)
		}
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
	routesTable := cfg.TablePrefix + "_routes"
	stateTable := cfg.TablePrefix + "_plugin_state"
	accessTable := cfg.TablePrefix + "_access"
	idxName := "idx_" + cfg.TablePrefix + "_real_ips_domain"
	idxIPName := "idx_" + cfg.TablePrefix + "_real_ips_ip"

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
	CREATE TABLE IF NOT EXISTS %s (
		prefix TEXT PRIMARY KEY,
		next_hop TEXT DEFAULT '',
		dev TEXT DEFAULT '',
		route_table TEXT DEFAULT '',
		created_at INTEGER DEFAULT 0
	);
	CREATE TABLE IF NOT EXISTS %s (
		key TEXT PRIMARY KEY,
		value TEXT NOT NULL DEFAULT ''
	);
	CREATE INDEX IF NOT EXISTS %s ON %s(domain);
	CREATE INDEX IF NOT EXISTS %s ON %s(real_ip);`,
		mapTable, ipTable, routesTable, stateTable, idxName, ipTable, idxIPName, ipTable,
	)

	if _, err := db.Exec(initSQL); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("init tables failed: %w", err)
	}
	// The access table is created even when the log is turned off, so enabling
	// it later does not need a migration step.
	if err := ensureAccessTable(db, accessTable); err != nil {
		_ = db.Close()
		return nil, err
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
		BP:                  bp,
		db:                  db,
		dbPath:              cfg.DBPath,
		tablePrefix:         cfg.TablePrefix,
		mapTable:            mapTable,
		ipTable:             ipTable,
		routesTable:         routesTable,
		cidr:                cfg.IPv4Range,
		prefix:              prefix,
		maxHosts:            maxHosts,
		ttl:                 cfg.TTL,
		recordTTL:           recordTTL,
		accessLog:           accessLog,
		accessTTL:           accessTTL,
		accessTable:         accessTable,
		nextHop:             strings.TrimSpace(cfg.NextHop),
		nextHopDev:          strings.TrimSpace(cfg.NextHopDev),
		realIP:              cfg.RealIP,
		timeLoc:             tzLoc,
		policyRuleSupported: supportsNamedRouteTable(),
		realRoutes:          make(map[string]struct{}),
		taskSem:             make(chan struct{}, defaultTaskConcurrency),
		taskInFlight:        make(map[string]struct{}),
		nftMirror:           make(map[string]string),

		hopSuffix:         cfg.HopNameSuffix,
		routeTable:        cfg.RouteTable,
		routeMark:         cfg.RouteMark,
		stateTable:        stateTable,
		routeRulePriority: routeRulePriority,
		tunRouteTable:     cfg.TunRouteTable,
		aggregateRoutes:   aggregateRoutes,
		mssClamp:          cfg.MSSClamp,
		useTun:            cfg.UseTun,
		tunDev:            strings.TrimSpace(cfg.TunDev),
		capturePrefixes:   capturePrefixes,
	}
	p.runner = execRunner{}
	p.probe = p.probeReachable
	p.egress = &egress.Direct{}
	p.conn = newConntrack(defaultConntrackSize, defaultConntrackTTL)
	p.runtime = newRuntimeMap()
	p.watch = newTrafficWatch()
	p.watchNames = newWatchNameCache(recordTTL)

	// The ledger is read once here: the sweep below and every later cleanup
	// work from this copy instead of querying SQLite again.
	ledgerCtx, ledgerCancel := context.WithTimeout(context.Background(), 15*time.Second)
	if err := p.loadLedger(ledgerCtx); err != nil {
		p.L().Warn("fakeip nat: load route ledger into memory failed", zap.Error(err))
	}
	ledgerCancel()

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
	if err := p.restoreRealIPs(restoreCtx); err != nil {
		p.L().Warn("fakeip nat: restore real ip table failed", zap.Error(err))
	}
	restoreCancel()

	// Stale mappings are dropped in the background, so a database that has been
	// growing for months does not need a manual vacuum.
	p.startRecordRetention()

	// Per-client rows are buffered and written in batches, so no SQLite call
	// sits on the answer path any more.
	p.startAccessFlusher()

	// Everything the data path needs is now in memory: the maintenance loop only
	// keeps the durable copies fresh.
	p.startMaintenance()

	// The proxy is the outlet of the tun data path only: the NAT data path is
	// kernel DNAT and never sees the connection. An unusable proxy degrades to
	// direct egress instead of blocking startup, but it is logged as an error.
	if cfg.RealIP && cfg.UseTun && !p.markRoutingEnabled() {
		p.L().Warn("realip has no effect with use_tun unless route_mark is set: without marks the answers keep their real addresses but nothing routes them into the device")
	}
	// Without marks every answer writes one host route to the real address, and
	// into the main table by default: that is a global change the whole box
	// pays for. Marks keep the same split in the plugin's own nft set.
	if cfg.RealIP && !cfg.UseTun && !p.markRoutingEnabled() {
		p.L().Warn("realip without route_mark writes one host route per answer into the routing table",
			zap.String("route_table", p.hostRouteTable()),
			zap.String("hint", "set route_mark to keep the split inside the plugin's nft set instead"))
	}
	if strings.TrimSpace(cfg.Egress) != "" {
		if cfg.Proxy != "" {
			return nil, fmt.Errorf("fakeip nat: egress and proxy are mutually exclusive, name one outlet")
		}
		outlet, ok := routepolicy.OutletFor(strings.TrimSpace(cfg.Egress))
		if !ok {
			return nil, fmt.Errorf("fakeip nat: egress %q is not declared before this plugin", cfg.Egress)
		}
		p.egress = outlet.OutletDialer()
		p.proxyActive = outlet.OutletProxyHost() != ""
		// The borrowed dialer is shared, so the fake range is added to its
		// exemptions: a socks5 outlet must keep the domain when local resolution
		// returns one of our own fake addresses.
		setFakeRange(p.egress, prefix)

		// A routed exit can also take the destinations this plugin maps, which
		// is the only correct owner for the non-tun path: the mark, the table
		// and the route are already installed by the exit, and a second copy
		// here would fight it.
		var registrar routepolicy.DestinationRegistrar
		if o, ok := outlet.(interface{ OutletDestSet() string }); ok && o.OutletDestSet() != "" {
			if r, ok := outlet.(routepolicy.DestinationRegistrar); ok {
				registrar = r
			}
		}
		p.borrowed = &borrowedExit{tag: outlet.OutletTag(), decision: outlet.OutletDecision(), registrar: registrar}

		fields, ignored := adoptExitFields(cfg, p.borrowed.decision, cfg.UseTun, registrar != nil)
		if len(ignored) > 0 {
			p.L().Warn("fakeip nat: these fields belong to the borrowed exit and are ignored here",
				zap.Strings("ignored", ignored), zap.String("egress", cfg.Egress),
				zap.String("exit", p.borrowed.decision.String()))
		}
		if fields.Mark != 0 {
			p.routeMark = fields.Mark
		}
		if fields.Table != "" {
			p.routeTable = fields.Table
		}
		if fields.Priority != 0 {
			p.routeRulePriority = fields.Priority
		}
		if fields.NextHop != "" {
			p.nextHop = fields.NextHop
		}
		if fields.Dev != "" {
			p.nextHopDev = fields.Dev
		}

		p.L().Info("fakeip nat: exit borrowed from another plugin",
			zap.String("egress", outlet.OutletTag()),
			zap.String("exit", p.borrowed.decision.String()),
			zap.Bool("proxy_active", p.proxyActive),
			zap.Bool("destination_registrar", registrar != nil))
		if !cfg.UseTun && p.proxyActive {
			p.L().Warn("the borrowed proxy only applies to the tun data path", zap.String("egress", cfg.Egress))
		}
		p.logStep("egress-borrow", time.Now())
	}

	if cfg.Proxy != "" {
		dialer, err := newEgress(cfg.Proxy, cfg.ProxyInsecure)
		if err != nil {
			return nil, err
		}
		// A socks5 link resolves the target with the host resolver. When this
		// plugin is also the host's DNS the answer is a fake ip of its own
		// range, so those answers are dropped and the domain is resolved on the
		// proxy side instead.
		if setFakeRange(dialer, prefix) {
			p.L().Debug("fakeip nat: socks5 outlet keeps the domain when local resolution returns a fake ip",
				zap.String("range", cfg.IPv4Range))
		}
		p.L().Debug("fakeip nat: proxy link parsed",
			zap.String("proxy", redactProxy(cfg.Proxy)),
			zap.String("outlet", egress.Describe(dialer)),
			zap.Bool("insecure", cfg.ProxyInsecure))
		if !cfg.UseTun {
			p.L().Warn("proxy is configured but use_tun is false; it only applies to the tun data path",
				zap.String("proxy", redactProxy(cfg.Proxy)))
		} else {
			// A gost link probes one flavour per protocol it may answer, so it
			// gets a budget that covers all of them instead of a single dial.
			probeBudget := 5 * time.Second
			if _, ok := dialer.(*egress.Gost); ok {
				probeBudget = 10 * time.Second
			}
			probeStarted := time.Now()
			probeCtx, probeCancel := context.WithTimeout(context.Background(), probeBudget)
			// Info, not Debug: when a start hangs, the last line before the gap
			// is what names the phase it hung in.
			p.L().Info("fakeip nat: probing proxy egress", zap.String("proxy", redactProxy(cfg.Proxy)))
			if err := probeEgress(probeCtx, dialer); err != nil {
				p.L().Warn("proxy is not usable, falling back to direct egress",
					zap.String("proxy", redactProxy(cfg.Proxy)), zap.Error(err))
			} else {
				p.egress = dialer
				p.proxyActive = true
				// A gost listener picks its protocol from the first bytes, so
				// the log names the flavours that actually answered: TCP is
				// ordered by handshake time, UDP only lists the ones whose
				// association was granted.
				if g, ok := dialer.(*egress.Gost); ok {
					p.L().Info("gost outlet protocols selected",
						zap.String("server", g.Server()),
						zap.Strings("tcp_protocols", g.TCPProtocols()),
						zap.Strings("udp_protocols", g.UDPProtocols()))
				}
				p.L().Info("proxy egress ready", zap.String("proxy", redactProxy(cfg.Proxy)))
			}
			probeCancel()
			p.logStep("proxy-probe", probeStarted)
		}
	}

	// IPv6 egress is the one input the DNS half cannot see: a fake IPv4 for an
	// IPv6-only name is useless unless the outlet can dial the address behind
	// it. The probe runs before the first answer so a restart decides with the
	// state of the link now, not with one from hours ago. A proxied outlet
	// needs no probe: it is told the domain and resolves it on the proxy side.
	if p.useTun && !p.realIP && !p.proxyActive {
		p.v6egress = newIPv6EgressProbe(cfg, ipv6ProbeInterval, p.L())
		if p.v6egress != nil {
			probeStarted := time.Now()
			p.v6egress.Start(context.Background(), p.L())
			p.logStep("ipv6-egress-probe", probeStarted)
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

	// An older build recorded nothing, so its mark rule can only be found from
	// the mark its nft table still carries. This runs before the stale nft
	// table is dropped, which is the only place that value survives.
	legacyStarted := time.Now()
	legacyCtx, legacyCancel := context.WithTimeout(context.Background(), natTimeout)
	p.sweepLegacyMarkPath(legacyCtx)
	legacyCancel()
	p.logStep("legacy-mark-sweep", legacyStarted)

	// The tun data path is the alternative to per-domain DNAT: it asks the
	// system for a device and routes the whole ipv4_range into it.
	if p.useTun {
		// A crash or a mode switch leaves the previous non-tun nft table behind,
		// and its DNAT chain still sits in prerouting: it rewrites the destination
		// before the route lookup, so the packet leaves through main instead of
		// the device. Tun mode owns no nft table, so the leftover goes first.
		staleCtx, staleCancel := context.WithTimeout(context.Background(), natTimeout)
		p.cleanupStaleNFTTable(staleCtx)
		staleCancel()

		// Same reason as the probe above: this line is the boundary between
		// "stuck before the device" and "stuck while bringing the device up".
		p.L().Info("fakeip nat: starting tun data path", zap.String("range", p.cidr))
		tunStarted := time.Now()
		if err := p.startTunDataPath(); err != nil {
			p.L().Error("use_tun is enabled but the tun data path could not start; the plugin has no outlet", zap.Error(err))
		} else {
			// The outlet is pinned only after the device exists: the range
			// address has to be assigned before it can be bound as a source.
			p.setupTunEgress()
			p.logStep("tun-data-path", tunStarted)
		}
	} else {
		// Switching away from tun leaves that run's outlet behind: a SNAT table
		// in postrouting and a policy rule for the range. The non-tun data path
		// does not wait for either, so the removal is queued.
		p.deferStartup("stale-tun-egress", func() {
			nftCtx, nftCancel := context.WithTimeout(context.Background(), natTimeout)
			defer nftCancel()
			p.cleanupStaleTunEgress(nftCtx)
		})
	}

	// A previous process may have stopped without cleaning up: a crash, a SIGKILL
	// or a configuration change all leave host routes behind. The sweep removes
	// one route per exec call, so it is queued instead of blocking Init: routes
	// of this run are in the ledger before they are written, and the sweep only
	// touches prefixes the ledger does not own.
	p.deferStartup("residual-routes", p.sweepResidualRoutes)

	// Capture prefixes are ledger rows too, and the sweep above deletes every
	// prefix the ledger names. Queueing the install behind it means the routes
	// are written after the leftovers are gone, instead of being swept as part
	// of this run's own record.
	if p.useTun && len(p.capturePrefixes) > 0 {
		p.deferStartup("capture-routes", p.installCaptureRoutes)
	}

	// A proxied outlet carries the answers itself, so in tun + fakeip the mark has
	// nothing to steer and stays uninstalled; the same configuration keeps the
	// mark active when no proxy answers. This is a run-time decision, not a
	// configuration error.
	if p.routeMark != 0 && p.useTun && !p.realIP && !p.markRoutingEnabled() {
		p.L().Debug("fakeip nat: route_mark inactive, the proxy carries the answers",
			zap.Uint32("route_mark", p.routeMark))
	}

	// Mark routing is installed after the sweep and before any resolution: the
	// sweep still has to clean the host routes an earlier shape wrote, and from
	// here on an address is only added to the nft set. A failure leaves
	// markActive false, which the data path reads as "keep writing host routes".
	markCtx, markCancel := context.WithTimeout(context.Background(), 10*time.Second)
	// A path this run is not going to use has to be removed by its recorded
	// identity, not by guessing: a previous run may have installed a different
	// mark or table, or route_mark may have been dropped from the configuration
	// altogether, and the objects would otherwise outlive every restart.
	prevMark, prevTable := p.loadMarkState(markCtx)
	switch {
	case p.markRoutingEnabled():
		if prevMark != 0 && (prevMark != p.routeMark || prevTable != p.routeTable) {
			p.removeStaleMarkPath(markCtx, prevMark, prevTable)
			p.clearMarkState(markCtx)
		}
		err := p.setupMarkRouting(markCtx)
		if err != nil {
			p.L().Error("route_mark is enabled but the mark routing could not be installed; falling back to host routes",
				zap.Uint32("route_mark", p.routeMark), zap.String("route_table", p.routeTable), zap.Error(err))
		} else if p.borrowed != nil && !p.useTun && p.borrowed.registrar != nil {
			// The exit installed and reads back its own objects, and it is the
			// one that removes them. Recording them as this plugin's state would
			// let a later start try to clean up someone else's exit.
			p.L().Debug("route mark: state belongs to the borrowed exit",
				zap.String("egress", p.borrowed.tag))
		} else {
			// Installing is not proof: read the four objects back so a silently
			// incomplete path shows up in the log instead of in the main table.
			p.reportMarkRouting(markCtx)
			p.saveMarkState(markCtx, p.routeMark, p.routeTable)
		}
	case prevMark != 0:
		// route_mark is gone from the configuration (or the tun+realip
		// combination that made it meaningful is): undo what the last run left.
		p.removeStaleMarkPath(markCtx, prevMark, prevTable)
		p.clearMarkState(markCtx)
	}
	markCancel()

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
		zap.Uint32("tun_mtu", p.tunMTU),
		zap.Duration("init_elapsed", time.Since(initStarted)))

	// Only cleanup is left in the queue, so it can start now that Init is done.
	p.startStartupQueue()
	return p, nil
}

// validateRouteMark checks the values the mark path has to turn into commands.
// It deliberately says nothing about which data path or which mode the run uses:
// a combination is never a configuration error, it only decides at run time
// whether the mark applies (see markRoutingEnabled). Rejecting combinations here
// used to take the whole resolver down on a start, which is what this signature
// of validation exists to avoid.
// borrowedExit is the exit named by egress: the fields it installed, and the
// registrar that accepts the addresses this plugin maps.
//
// Two data paths read it differently. The tun path only mirrors the decision
// so its logs name the real owner. The NAT path uses the registrar instead of
// writing its own nft set, rule and default route, because those are exactly
// the objects the exit already owns.
type borrowedExit struct {
	tag       string
	decision  routepolicy.Decision
	registrar routepolicy.DestinationRegistrar
}

// borrowedExitFields is the routing half a borrower takes from the exit it
// pointed at with egress. egress_route owns mark, table, priority and next hop
// for one piece of kernel state; repeating any of them in this plugin would let
// two places disagree about the same exit.
type borrowedExitFields struct {
	Mark     uint32
	Table    string
	Priority int
	NextHop  string
	Dev      string
}

// adoptExitFields resolves what the borrowed exit replaces, and names the
// fields the operator also wrote here so the log can say they were dropped
// instead of letting them look effective.
//
// The tun data path consumes none of the mark, table or rule priority: it pins
// the fake range into the main table and hands packets to its own stack. They
// are still adopted so the admin view and the log report the exit's real
// decision instead of a stale local copy.
//
// The NAT data path does install those objects, but only when the exit cannot
// take destinations itself. A routed exit already writes the mark, the table
// and the rule, so a borrower that repeated them would collide with the exit's
// claim; when it offers a destination set, the borrower registers the mapped
// addresses there and keeps its hands off the kernel.
func adoptExitFields(cfg *Args, d routepolicy.Decision, useTun bool, canRegister bool) (borrowedExitFields, []string) {
	declared := map[string]bool{
		"route_mark":          cfg.RouteMark != 0,
		"route_table":         strings.TrimSpace(cfg.RouteTable) != "" && strings.TrimSpace(cfg.RouteTable) != "main",
		"route_rule_priority": cfg.RouteRulePriority != 0 && cfg.RouteRulePriority != defaultRouteRulePriority,
		"next_hop":            strings.TrimSpace(cfg.NextHop) != "",
		"next_hop_dev":        strings.TrimSpace(cfg.NextHopDev) != "",
	}

	owned := []string{"next_hop", "next_hop_dev"}
	if useTun || canRegister {
		owned = []string{"route_mark", "route_table", "route_rule_priority", "next_hop", "next_hop_dev"}
	}
	var ignored []string
	for _, name := range owned {
		if declared[name] {
			ignored = append(ignored, name)
		}
	}

	out := borrowedExitFields{NextHop: d.NextHop, Dev: d.Dev}
	if useTun || canRegister {
		// The exit installed these, so the reported decision matches the owner.
		out.Mark, out.Table, out.Priority = d.Mark, d.Table, d.Priority
	}
	return out, ignored
}

func validateRouteMark(cfg *Args, routeRulePriority int) error {
	if cfg.RouteMark == 0 {
		return nil
	}
	if routeRulePriority < 1 || routeRulePriority > 32766 {
		return fmt.Errorf("invalid route_rule_priority %d: must be between 1 and 32766", routeRulePriority)
	}
	if !supportsNamedRouteTable() {
		return fmt.Errorf("route_mark is only supported on linux")
	}
	// Piling marks into main is the shape this option exists to avoid.
	if cfg.RouteTable == "main" {
		return fmt.Errorf("route_mark needs route_table to name a dedicated table, not main")
	}
	return nil
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
	// The device answers a traceroute probe as a hop, so it must speak as a
	// stand-in address of the range: its own address is dropped by the
	// receiving host as a martian source.
	st.virtualSrc = p.hopFakeFor
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

// markAnsweredIPs adds the real destinations of one answer to the mark set, off
// the answer path: the nft write is one exec call and the client does not need
// the element to exist before it is told the fake ip.
func (p *FakeIPNatPlugin) markAnsweredIPs(ips []string) {
	if len(ips) == 0 {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), natTimeout)
		defer cancel()
		if err := p.markRealIPs(ctx, ips); err != nil {
			p.L().Warn("fakeip nat: marking the answered real ips failed",
				zap.Strings("real_ips", ips), zap.Error(err))
		}
	}()
}

// startRouteAggregation runs the managed-route collapse on a timer. The scan
// reads the routing table, not a memory set, so host routes written by an
// earlier process are collapsed too. Only the NAT data path needs it: the tun
// data path routes the whole fake range as one prefix already.
func (p *FakeIPNatPlugin) startRouteAggregation() {
	if p.useTun || !p.aggregateRoutes {
		return
	}
	// Under mark routing the mapped addresses never enter a routing table, so
	// there is nothing for the scan to fold or prune.
	if p.markActiveNow() {
		p.L().Debug("fakeip nat: route aggregation not needed under route_mark")
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
	p.stopMaintenance()
	// The routes are about to be deleted, so the record is flushed once before
	// that: a crash in the middle of the cleanup still leaves a complete ledger.
	flushCtx, flushCancel := context.WithTimeout(context.Background(), natTimeout)
	p.flushLedger(flushCtx)
	flushCancel()
	p.startupWG.Wait()
	p.cleanupDataPath()
	p.stopRecordRetention()
	p.stopAccessFlusher()
	p.stopTunDataPath()
	p.stopTunEgress()
	p.stopTrafficWatch()
	p.v6egress.Stop()
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
		// Addresses carried inside an A answer. Unusual, but some upstreams
		// leave an AAAA there, and it is free proof the name is usable over
		// IPv6.
		var answerV6 []string
		for _, ans := range resp.Answer {
			switch rr := ans.(type) {
			case *dns.A:
				realIPs = append(realIPs, rr.A.String())
			case *dns.AAAA:
				answerV6 = append(answerV6, rr.AAAA.String())
			}
		}
		hasAAAA := len(answerV6) > 0

		// An IPv6-only name needs a fake IPv4 before any client can reach it.
		// Two outlets can carry it: a proxy dials the domain and does not need
		// an address, while a direct tun outlet dials the address itself and
		// therefore needs a working IPv6 egress. The direct case is decided by
		// the egress probe rather than by the query: with no IPv6 path the
		// answer stays empty, which is what a host without IPv6 always produced.
		ipv6Only := false
		// dialIPs holds the addresses a direct outlet may dial. The proxy path
		// leaves it empty on purpose: it is told the domain, not the address.
		var dialIPs []string
		if len(realIPs) == 0 && !p.realIP && resp.Rcode == dns.RcodeSuccess {
			domain := strings.TrimSuffix(question.Name, ".")
			switch {
			case p.proxyActive:
				if p.runtime != nil {
					if _, ok := p.runtime.fakeOf(domain); ok {
						ipv6Only = true
					}
				}
				if !ipv6Only && (hasAAAA || len(p.domainAAAAs(ctx, qCtx, next)) > 0) {
					ipv6Only = true
				}
			case p.ipv6DirectReady():
				dialIPs = answerV6
				if len(dialIPs) == 0 && p.runtime != nil {
					// A mapping answered earlier already recorded the addresses,
					// so the common repeat query costs no extra upstream lookup.
					dialIPs = p.runtime.v6Of(domain)
				}
				if len(dialIPs) == 0 {
					dialIPs = p.domainAAAAs(ctx, qCtx, next)
				}
				ipv6Only = len(dialIPs) > 0
			}
			if ipv6Only {
				p.L().Debug("fakeip nat: ipv6-only domain allocated",
					zap.String("domain", domain),
					zap.Bool("proxy_outlet", p.proxyActive),
					zap.Int("dial_addresses", len(dialIPs)))
			}
		}

		if len(realIPs) > 0 || ipv6Only {
			domain := strings.TrimSuffix(question.Name, ".")
			// recorded is what goes into the real-ip table and the data path.
			// The proxy path stores nothing for these names: its mapping is the
			// domain, and a fake row would only be mistaken for a dialable one.
			recorded := realIPs
			if len(realIPs) == 0 && len(dialIPs) > 0 {
				recorded = dialIPs
				p.L().Debug("fakeip nat: ipv6 destinations recorded",
					zap.String("domain", domain), zap.Strings("real_ips", dialIPs))
			}
			if len(recorded) > 0 {
				p.L().Debug("fakeip nat: real ips collected",
					zap.String("domain", domain), zap.Int("count", len(recorded)), zap.Strings("real_ips", recorded))
				p.learnWatchRealIPs(domain, recorded)
			}
			if p.realIP {
				// Pure routing mode: the answer keeps the real IPs and the
				// plugin only steers each of them out of the chosen gateway.
				p.L().Debug("fakeip nat: realip mode keeps real answers",
					zap.String("domain", domain), zap.Strings("real_ips", realIPs))
				go p.syncRealRoutes(context.Background(), realIPs)
			} else {
				fakeIP, err := p.recordAndAllocate(ctx, domain, recorded)
				if err != nil {
					p.L().Error("sqlite record fakeip failed", zap.String("domain", domain), zap.Error(err))
				} else if fakeAddr, err := netip.ParseAddr(fakeIP); err != nil {
					// A leftover "pending" row or a corrupted value must never
					// produce an A record with a nil IP.
					p.L().Error("invalid allocated fake ip", zap.String("domain", domain), zap.String("fake_ip", fakeIP), zap.Error(err))
				} else {
					// tun + fakeip learns its real destinations from the answer
					// rather than from a DNAT write, so this is where the mark
					// set is fed. The write is not on the answer path: the client
					// may not connect for another few milliseconds. The set is
					// typed `ip`, so an IPv6 address would be rejected there and
					// is never needed: the mark path only steers IPv4 dials.
					if p.useTun && p.markActiveNow() {
						p.markAnsweredIPs(onlyIPv4(recorded))
					}
					// Wait for the data plane before answering: a client that
					// receives a fake IP while the DNAT entry is still missing
					// can only fail, which is what "the mapping exists but the
					// client got a real IP" looked like from the outside.
					ready := p.dispatchNAT(ctx, fakeIP, domain, strings.Join(recorded, ","))
					if !ready {
						p.L().Warn("nat mapping not ready, answering fake ip anyway",
							zap.String("domain", domain), zap.String("fake_ip", fakeIP))
					}
					p.L().Debug("fakeip nat: fake ip answered",
						zap.String("domain", domain), zap.String("fake_ip", fakeIP),
						zap.Uint32("ttl", p.ttl), zap.Bool("data_plane_tun", p.useTun))
					// Who asked for it: the answer is already decided, so a
					// failed write only costs one log line.
					p.recordAccess(qCtx, domain, fakeIP)

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

// domainAAAAs asks the rest of the chain for the AAAA records of the name. It
// runs when an A answer came back empty and the outlet can still carry an
// IPv6-only name. The query goes through the same chain as the original A
// query, so cache and upstream selection stay consistent, and it produces the
// addresses a direct outlet dials rather than a boolean.
//
// next must be a node that can answer a query: when this plugin sits at the end
// of its sequence there is nothing to ask, and the caller keeps the empty answer.
func (p *FakeIPNatPlugin) domainAAAAs(ctx context.Context, qCtx *query_context.Context, next executable_seq.ExecutableChainNode) []string {
	if next == nil {
		return nil
	}
	q := qCtx.Q()
	if len(q.Question) == 0 {
		return nil
	}
	aaaaQ := q.Copy()
	aaaaQ.Question[0].Qtype = dns.TypeAAAA
	aaaaCtx := query_context.NewContext(aaaaQ, qCtx.ReqMeta())
	if err := executable_seq.ExecChainNode(ctx, aaaaCtx, next); err != nil {
		p.L().Debug("fakeip nat: aaaa lookup for ipv6-only domain failed",
			zap.String("name", q.Question[0].Name), zap.Error(err))
		return nil
	}
	resp := aaaaCtx.R()
	if resp == nil || resp.Rcode != dns.RcodeSuccess {
		return nil
	}
	var addrs []string
	for _, ans := range resp.Answer {
		if rr, ok := ans.(*dns.AAAA); ok {
			if addr, err := netip.ParseAddr(rr.AAAA.String()); err == nil && addr.Is6() {
				addrs = append(addrs, addr.String())
			}
		}
	}
	return addrs
}

// recordAndAllocate returns a stable fake ip for domain and records the
// currently resolved real ips. It is idempotent across processes: concurrent
// instances race on INSERT ... ON CONFLICT DO NOTHING instead of UNIQUE errors.
func (p *FakeIPNatPlugin) recordAndAllocate(ctx context.Context, domain string, realIPs []string) (string, error) {
	now := time.Now().Unix()

	// Fast path: a domain that already owns an address is answered straight
	// from the memory mirror. The row is written once, when the address is
	// allocated, so a re-resolution - which happens once per cache TTL - must
	// not pay an INSERT, a SELECT and a real-ip upsert again. All three are
	// serialized on the single SQLite connection, and the mirror is restored
	// from the database at startup and updated by every allocation and admin
	// write, so it always agrees with the durable copy.
	if p.runtime != nil {
		if fakeIP, ok := p.runtime.fakeOf(domain); ok && !isPendingFakeIP(fakeIP) {
			if err := p.upsertRealIPs(ctx, domain, realIPs, now); err != nil {
				p.L().Warn("upsert real ips failed", zap.String("domain", domain), zap.Int("ip_count", len(realIPs)), zap.Error(err))
			}
			p.runtime.touch(domain, now)
			return fakeIP, nil
		}
	}

	// Real ips are idempotent upserts, so they do not need the allocation lock.
	if err := p.upsertRealIPs(ctx, domain, realIPs, now); err != nil {
		p.L().Warn("upsert real ips failed", zap.String("domain", domain), zap.Int("ip_count", len(realIPs)), zap.Error(err))
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	insertSQL := fmt.Sprintf("INSERT INTO %s (domain, fake_ip, created_at, last_seen) VALUES (?, ?, ?, ?) ON CONFLICT(domain) DO NOTHING", p.mapTable)
	if _, err := p.db.ExecContext(ctx, insertSQL, domain, pendingFakeIPFor(domain), now, now); err != nil {
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
	if !isPendingFakeIP(fakeIP) {
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
		res, err := p.db.ExecContext(ctx, updateSQL, allocated, now, id, fakeIP)
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
			if !isPendingFakeIP(fakeIP) {
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

// sameIPList reports whether two address lists carry the same addresses in the
// same order, which is what an unchanged answer produces.
func sameIPList(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// upsertRealIPs stores all real ips of domain in one round trip. The memory
// table is refreshed on every answer because it is what a lookup reads, while
// the durable copy is written at most once per realIPWriteInterval: the
// database is only the restart fallback, and a write per answer was the largest
// remaining piece of work on the answer path.
func (p *FakeIPNatPlugin) upsertRealIPs(ctx context.Context, domain string, realIPs []string, now int64) error {
	kept := make([]string, 0, len(realIPs))
	seen := make(map[string]struct{}, len(realIPs))
	for _, ip := range realIPs {
		if _, ok := seen[ip]; ok {
			continue
		}
		seen[ip] = struct{}{}
		// An upstream that answered with one of this plugin's own fake
		// addresses must not be stored as a real ip: every later lookup would
		// hand that address to an outlet and turn into a dead dial.
		if p.isFakeAddrString(ip) {
			p.L().Debug("fakeip nat: dropping fake ip from the real ip list",
				zap.String("domain", domain), zap.String("real_ip", ip))
			continue
		}
		kept = append(kept, ip)
	}
	if len(kept) == 0 {
		return nil
	}
	// The memory table takes the same rows, so the next lookup is answered
	// without asking SQLite again. Only a write that would repeat exactly what
	// is already stored is throttled: when the answer changed the address list
	// the durable copy is stale and has to be refreshed now, whatever the
	// interval says.
	write := true
	if p.runtime != nil {
		changed := !sameIPList(p.runtime.realsOf(domain), kept)
		p.runtime.putReal(domain, kept)
		if changed {
			p.runtime.markWritten(domain, now)
		} else {
			write = p.runtime.dueForWrite(domain, now, realIPWriteInterval)
		}
	}
	if !write {
		return nil
	}

	var b strings.Builder
	b.WriteString("INSERT INTO ")
	b.WriteString(p.ipTable)
	b.WriteString(" (domain, real_ip, last_seen) VALUES ")
	args := make([]interface{}, 0, len(kept)*3)
	for i, ip := range kept {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString("(?,?,?)")
		args = append(args, domain, ip, now)
	}
	b.WriteString(" ON CONFLICT(domain, real_ip) DO UPDATE SET last_seen = excluded.last_seen")
	if _, err := p.db.ExecContext(ctx, b.String(), args...); err != nil {
		// The durable copy is still missing these rows, so the next answer has
		// to try again instead of waiting out the throttle window.
		if p.runtime != nil {
			p.runtime.forgetWrite(domain)
		}
		return err
	}
	return nil
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
