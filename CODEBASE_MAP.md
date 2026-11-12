# mosdns-v4 代码库功能地图

> 本文是对当前工作树（`/Users/macos/mosdns-v4`，module `github.com/ersonw/mosdns-v4`）的**只读梳理**，描述「现状是什么、在哪实现、改哪里会牵动谁」，不含重构方案与代码审查结论。
> 行号对应当前工作树，代码变动后需重新核对。

---

## 0. 30 秒导读

- 这是一个 **mosdns v4 的定制分支**（上游 IrineSistiana/mosdns），在原有插件框架上加了 `exec_script`、`fakeip_nat`、`udpme://` 上游等定制能力。
- 全仓 **173 个 Go 文件 / 24,178 行**；核心只有 6 个概念：`coremain`（框架）、`plugin`（插件）、`pkg`（底座）、`tools`（CLI）、`mlog`（日志）、`main.go`（入口）。
- 运行模型是**单向执行链**：一个 DNS 查询从 `EntryHandler.ServeDNS` 进来，被 `sequence` 编译出的链节点依次 `Exec(ctx, qCtx, next)`，谁不调 `next` 谁就终结这条链（`_return` 就是干这个的）。
- **新增功能的三种落点**：改一个查询的处理 → 写 `plugin/executable/xxx`；加一种判断条件 → 写 `plugin/matcher/xxx`；加通用能力 → 写 `pkg/xxx` 再被插件引用。
- 加插件后**必须**在 `plugin/enabled_plugin.go:23-51` 加空白导入，否则 `init()` 不执行、配置直接报 `plugin type X not defined`。

---

## 1. 规模与身份

| 项 | 值 |
|---|---|
| module | `github.com/ersonw/mosdns-v4` |
| 版本变量 | `main.go:34` `version = "dev/4.0"` |
| Go 文件 / 总行数 | 173 / 24,178 |
| `pkg` 下包数 | 35 |
| 插件目录 | 27（25 executable + 2 matcher） |
| 可通过 `type` 配置的插件 | 24 |
| 预置插件 tag | 21 |
| CLI 子命令 | `start`、`service`、`version`、`probe`、`v2dat`、`config gen/conv` |

---

## 2. 目录 → 职责总表

| 目录 / 文件 | 承担什么 | 关键文件 | 对外接口 |
|---|---|---|---|
| `main.go` | 进程入口；注册 `version`；空白导入 `plugin`、`tools` 触发所有 `init()` | `main.go` | — |
| `coremain/run.go` | cobra 命令树；viper 读配置；`include` 递归合并；启动/服务模式 | `run.go:43-95`、`97-136`、`144-184` | `AddSubCmd`、`Run`、`StartServer` |
| `coremain/config.go` | 全部 YAML 配置结构体 | `config.go:28-99` | `Config`、`PluginConfig`、`ServerConfig`、`ServerListenerConfig`、`APIConfig`、`SecurityConfig` |
| `coremain/register.go` | **插件类型注册表** + **预置插件注册表** + `BP` 基类 + `NewPlugin` 参数解码 | `register.go:53-118`、`139-159`、`163-208` | `RegNewPluginFunc`、`RegNewPersetPluginFunc`、`NewPlugin`、`BP` |
| `coremain/mosdns.go` | 实例装配：logger、dataManager、execs、matchers、HTTP API mux、Prometheus、bad IP observer；启动 server / API | `mosdns.go:62-200`、`202-245` | `GetExecutables`、`GetMatchers`、`GetDataManager`、`GetHTTPAPIMux`、`GetMetricsReg`、`GetBadIPObserver`、`GetSafeClose` |
| `coremain/server.go` | 把 `ServerConfig` 落到具体监听协议；Unix socket 生命周期 | `server.go:23-58`、`60-171` | 内部 |
| `coremain/service.go` | 系统服务（安装/卸载/启停）| `service.go:33-57` 起 | `service` 子命令 |
| `coremain/interface.go` | 三种插件接口定义 | `interface.go:28-44` | `Plugin`、`ExecutablePlugin`、`MatcherPlugin` |
| `mlog/` | zap logger 构建（level / file / err_file / info_file）| `logger.go:29-34`、`45+` | `NewLogger`、全局 `S()`/`L()` |
| `plugin/enabled_plugin.go` | **插件启用清单**（27 个空白导入）| `enabled_plugin.go:23-51` | — |
| `plugin/executable/*` | 26 个可执行插件（改查询/改响应/转发/缓存/落盘/管理面）| 见 `PLUGIN_INDEX.md` | `Executable` |
| `plugin/matcher/*` | 2 个匹配器插件（`query_matcher`、`response_matcher`）| 同上 | `Matcher` |
| `pkg/` | 可复用底座：上下文、链、匹配器、缓存、上游、服务端、池化、工具 | 见 §5 | — |
| `tools/` | CLI 子命令：`probe`（连通/复用探测）、`v2dat`（解 v2ray dat）、`config`（生成/转换）| `tools/init.go:27-55` | — |

---

## 3. 启动到回包的完整链路

```
main.main()                                  main.go:47
 └ coremain.Run()                            run.go:93
   └ rootCmd.Execute()                       run.go:94
     └ StartServer(serverFlags)              run.go:97
       ├ GOMAXPROCS / chdir                  run.go:98-108
       ├ viper 读 config（-c 或 ./config）    run.go:110-120
       ├ mapstructure 解码 → *Config          run.go:122-125
       │   ErrorUnused=true / TagName=yaml / WeaklyTypedInput=true   run.go:138-142
       ├ mergeInclude（深度 ≤8，检测环）      run.go:128-130, 144-184
       └ RunMosdns(cfg)                      mosdns.go:62
         ├ NewLogger / maps / mux / metrics  mosdns.go:63-78
         ├ bad ip observer（threshold>0 才建）mosdns.go:86-108
         ├ data_providers 装配               mosdns.go:112-126
         ├ 预置插件装配                      mosdns.go:129-135
         ├ plugins 装配                       mosdns.go:139-159
         ├ startServers                      mosdns.go:164-168 → server.go:23
         └ api http server（cfg.api.http）    mosdns.go:171-190
```

请求路径：

```
listener (udp/tcp/dot/doh）
 └ pkg/server（udp:22 / tcp:40 / dot:28 / doh:31,35）
   └ dns_handler.EntryHandler.ServeDNS       entry_handler.go:95
     ├ ctx 加 deadline（默认 5s）             entry_handler.go:97-103
     ├ query_context.NewContext(req, meta)   context.go:66
     ├ entry.Exec(ctx, qCtx, nil)            entry_handler.go:107
     │   └ sequence → executable_seq.ExecChainNode(...)  utils.go:71
     ├ resp := qCtx.R()                      entry_handler.go:108
     ├ nil 或 err → SERVFAIL                 entry_handler.go:118-122
     └ RecursionAvailable = true             entry_handler.go:124-126
```

要点：

- `ServerConfig.Exec` 必须能在 `m.execs` 里找到（`server.go:31-34`），也就是说入口必须是一个**可执行插件**（通常是 `sequence`）。
- 查询超时默认 5s（`coremain/server.go:18`），监听器 idle 超时默认 10s（`:19-21`）。
- 插件只要实现了 `http.Handler`，会被自动挂到 `/plugins/<tag>/`（`mosdns.go:156-158`）；目前只有 `reverse_lookup` 用了这条路（`reverse_lookup.go:124`）。
- 全部插件初始化失败都会**终止启动**（`mosdns.go:149-152`），不存在「跳过坏的插件继续跑」。

---

## 4. 核心抽象

### 4.1 插件三件套

| 类型 | 定义 | 必须实现 | 装配去向 |
|---|---|---|---|
| `Plugin` | `interface.go:28` | `Tag()`、`Type()`、`Close()` | — |
| `ExecutablePlugin` | `interface.go:35` | 上面 + `Exec(ctx, qCtx, next)` | `m.execs[tag]`（`mosdns.go:204-206`）|
| `MatcherPlugin` | `interface.go:41` | 上面 + `Match(ctx, qCtx) (bool, error)` | `m.matchers[tag]`（`mosdns.go:207-209`）|

`BP`（`register.go:163-208`）是所有插件的公共基类，提供：

- `Tag()` / `Type()`
- `L()` / `S()`：带 tag 命名的 zap logger
- `M()`：拿 `*Mosdns`，从而访问 `GetExecutables()`、`GetDataManager()`、`GetMetricsReg()`、`GetHTTPAPIMux()`、`GetBadIPObserver()`
- `GetMetricsReg()`：自动加 `plugin_<tag>_` 前缀（`register.go:202-204`）

### 4.2 执行链语义

```go
// pkg/executable_seq/iface.go:27
type Executable interface {
    Exec(ctx context.Context, qCtx *query_context.Context, next ExecutableChainNode) error
}
```

- 节点通过 `LinkNext` 串成单向链表（`iface.go:57-73`），`ExecChainNode` 自动把 `n.Next()` 传进去（`utils.go:71-78`）。
- **调用 `next` = 继续往下走；不调 `next` = 本条链到此结束**。响应统一放 `qCtx.SetResponse(r)`，由入口统一取。
- 常见三种写法：
  - 透传型：干活后 `return executable_seq.ExecChainNode(ctx, qCtx, next)`
  - 短路型：命中就 `qCtx.SetResponse(r); return nil`（如 `hosts` `hosts.go:79-87`、`arbitrary` `arbitrary.go:49-55`）
  - 后置型：先调 `next`，再改 `qCtx.R()`（如 `ttl` `ttl.go:61-71`、`ipset` `ipset_linux.go:64-74`）

### 4.3 四种结构节点（`exec` 里能写的「语法」）

`BuildExecutableLogicTree`（`executable_sequence.go:36-108`）根据 map 的 key 决定节点类型：

| 配置 key | 节点 | 关键字段 | 语义 | 实现 |
|---|---|---|---|---|
| `if` / `if_and` | `ConditionNode` | `if`、`exec`、`else_exec` | govaluate 表达式求值，真走 `exec`，假走 `else_exec`，两者都为空则直通 | `if_node.go:32-38`、`231-245` |
| `parallel` | `ParallelNode` | 子任务列表 | 并发跑多个子链，谁的响应先到就用谁 | `parallel.go:46` |
| `load_balance` | `LBNode` | 多个子链 | 按权重/随机选一条 | `load_balance.go:52` |
| `primary` / `secondary` | `FallbackNode` | `stat_length`、`threshold`、`fast_fallback`、`always_standby` | 主失败/超时切备 | `fallback.go:33-47`、`106` |

字符串数组 = 顺序链（`executable_sequence.go:49-67`）；字符串 = 按 tag 查 `m.execs`（`:69-74`）。

### 4.4 匹配器与 `if` 表达式

- `Matcher`：`Match(ctx, qCtx) (bool, error)`（`iface.go:38-41`）。
- `query_matcher` / `response_matcher` 内部都是**多个 matcher 的逻辑与**（`LogicalAndMatcherGroup`，`utils.go:118-132`），空组返回 `false`。
- `if:` 里的每个变量必须是**已注册的 matcher tag**，`newConditionMatcher` 在**编译期**用 `expr.Vars()` 逐个查表，查不到直接报错（`if_node.go:119-125`）；并且会用 `ChecksTypes = true` 试算一次（`:128-135`）。
- 求值时的参数是懒加载闭包（`if_node.go:205-229`），表达式短路的变量不会被调用。

### 4.5 `qCtx` 与 marks

| 字段 / 方法 | 说明 | 位置 |
|---|---|---|
| `Q()` | 当前查询（**可被插件改写**，如 `redirect` 改 `Question[0].Name`）| `context.go:107` |
| `OriginalQuery()` | 进入时的副本，**不该被修改** | `context.go:114`、`:77` |
| `ReqMeta()` | 客户端地址、是否来自 UDP | `context.go:121` |
| `R()` / `SetResponse()` | 响应读写（只存指针，存完别再动）| `context.go:126-135` |
| `Id()` / `StartTime()` | 全局自增查询号 / 创建时间 | `context.go:140-147` |
| `AddMark` / `HasMark` | 位标记，用于跨插件传递状态（`marker` 插件分配）| `context.go:179-209` |
| `Copy()` / `CopyTo()` | 深拷贝（`parallel` 分支各用一份）| `context.go:155-177` |

> **`context.go:47` 明确写了「所有 Context 方法都不是并发安全的」**。并行链里每个分支必须用 `Copy()`，否则数据竞争。

---

## 5. `pkg` 底座索引（35 个包）

| 包 | 做什么 | 谁在用 |
|---|---|---|
| `query_context` | 查询上下文、响应、marks、复制 | 所有插件与 server |
| `executable_seq` | 执行链接口、链构建、`if`/`parallel`/`load_balance`/`fallback` 节点 | `sequence`、`cache`、`hosts` 等 |
| `list` | 侵入式泛型双向链表（给 `lru` 用）| `lru` |
| `lru` / `concurrent_lru` / `concurrent_map` | LRU 与并发 map 容器 | `cache`、`reverse_lookup`、`bad_ip_observer` |
| `concurrent_limiter` | 按 IP/前缀的令牌桶限速（`HPClientLimiter`）| `client_limiter`、`bad_ip_observer` |
| `ip_observer` | 记录「坏 IP」并提供 `/security/bad_ip_observer` HTTP 视图 | `coremain`、`client_limiter` |
| `data_provider` | 外部数据文件 + fsnotify 热重载 + 监听者列表 | `domain`/`netlist` 加载助手、`hosts`、`redirect` |
| `matcher/domain` | 域名匹配器（full / domain / keyword / regexp / mix）、文本与 geosite 加载 | `query_matcher`、`hosts`、`redirect`、`zone_file` 之外的大多数域名判断 |
| `matcher/netlist` | IP/CIDR 列表匹配、geoip dat 加载、动态重载 | `query_matcher`、`response_matcher` |
| `matcher/msg_matcher` | 把「域名/IP/QType/QClass/ECS/RCode/CNAME」判断套到 DNS 消息上 | 两个 matcher 插件 |
| `matcher/elem` | 整数集合匹配（QType、RCode）| `msg_matcher`、`query_matcher`、`response_matcher` |
| `matcher/v2data` | v2ray dat 格式 protobuf 定义 | geosite/geoip 加载 |
| `zone_file` | 解析 zone 文本并回答（`Lookup`/`Reply`）| `arbitrary` |
| `hosts` | hosts 文件语义（域名 → IPv4/IPv6 集合）| `hosts` |
| `dnsutils` | DNS 消息工具：TTL 调整、ECS 读写、EDNS0 padding、msg key | `ttl`、`ecs`、`padding`、`cache`、`misc_optm` |
| `cache` | 缓存后端接口（Get / Store / Len / Close）| `cache`、`reverse_lookup` |
| `cache/mem_cache` | 分片内存缓存 | 同上 |
| `cache/redis_cache` | Redis 后端（时间戳打包进 value）| 同上 |
| `upstream` | `Upstream` 接口 + 按地址协议构造（udp/tcp/dot/doh）| `forward`、`fast_forward` |
| `upstream/doh` | DoH 客户端 | `upstream` |
| `upstream/transport` | 复用连接池（TCP/DoT，pipeline、max_conns）| `upstream` |
| `upstream/bootstrap` | 上游域名解析（bootstrap DNS）| `upstream` |
| `upstream/h3roundtripper` | DoH over HTTP/3 | `upstream` |
| `bundled_upstream` | 多上游「并发取最快」的 `ExchangeParallel` | `fast_forward` |
| `server` | 服务端基座：ServeUDP / ServeTCP / ServeTLS / ServeHTTP / ServeHTTPS | `coremain/server.go` |
| `server/dns_handler` | 入口 handler：超时、建 Context、SERVFAIL 兜底 | 所有监听协议 |
| `server/http_handler` | DoH/HTTP 的请求解析（GET/POST、`get_user_ip_from_header`）| `server` |
| `nftset_utils` | nftables set 写入（仅 linux）| `nftset` |
| `pool` | buffer / timer / msg buffer 池，降低 GC | `dnsutils`、`server`、`sleep`、`cache` |
| `safe_close` | 优雅关闭信号汇聚 | `coremain`、`data_provider` |
| `utils` | 弱解码、证书池、数字默认值、PTR 名解析、地址工具 | 全仓 |
| `ext_exec` | 执行外部命令并取输出 | 旧路径（当前 `exec_script` 自己用 `os/exec`）|

---

## 6. 按能力查位置（功能索引）

| 我想找 / 改的能力 | 去哪里看 |
|---|---|
| 配置怎么读、`include` 怎么合并 | `coremain/run.go:97-184` |
| 配置有哪些字段 | `coremain/config.go:28-99` |
| 插件怎么注册、参数怎么解码 | `coremain/register.go:53-118` |
| 哪些插件被启用 | `plugin/enabled_plugin.go:23-51` |
| 服务器有哪些协议、怎么分发 | `coremain/server.go:100-155`、`pkg/server/*.go` |
| 查询超时 / idle 超时默认值 | `coremain/server.go:18-21`、`:36-39`、`:67-70` |
| 无响应时为什么回 SERVFAIL | `pkg/server/dns_handler/entry_handler.go:108-127` |
| 链式执行、`if`/`parallel`/`fallback` 语义 | `pkg/executable_seq/*.go` |
| 域名匹配规则（full/domain/keyword/regexp）| `pkg/matcher/domain/matcher.go:29-33`、`:187-192` |
| IP 段匹配 | `pkg/matcher/netlist/list.go`、`load_helper.go` |
| geosite / geoip dat 加载 | `pkg/matcher/domain/load_helper.go:340`、`netlist/load_helper.go:237` |
| 外部数据文件热重载 | `pkg/data_provider/data_provider.go:152-222` |
| 缓存命中 / 懒更新 / 写 Redis | `plugin/executable/cache/cache.go`、`pkg/cache/*` |
| 上游连接复用 / pipeline / HTTP3 | `pkg/upstream/transport/transport.go`、`upstream/upstream.go:113` |
| 多上游并发取最快 | `pkg/bundled_upstream`、`fast_forward.go:186-193` |
| ECS 写入与回包剥离 | `plugin/executable/ecs/ecs.go:122-139`、`pkg/dnsutils/edns0_ecs.go` |
| EDNS0 padding | `plugin/executable/padding/padding.go:57-79`、`pkg/dnsutils/edns0_padding.go` |
| TTL 上下限 | `plugin/executable/ttl/ttl.go:61-71`、`pkg/dnsutils/msg.go:69-74` |
| 写 ipset / nftables | `ipset/ipset_linux.go:80-112`、`nftset/nftset_linux.go:90-138` |
| 假 IP + NAT 映射 | `fakeip_nat/fakeip_nat.go:289-358`（Exec）、`:360-499`（分配 / 落库 / 派发）；`fakeip_nat/nat.go:71`（`syncNAT` nftables 同步、`applyHostRoute:252`、`aggregateManagedRoutes:300`、`pruneManagedRoutes:332`、`collapseManagedRoutes:354`、`cleanupDataPath:462`、`knownRealIPs:517`、`syncRealRoutes:615`）、`fakeip_nat/nat.go:854`（`cleanupStaleNFTTable`：tun 模式启动前清掉上次非 tun 遗留的 nft 表）、`fakeip_nat/route_ledger.go`（受管路由账本：`rememberManagedRoute:33`/`sweepLedgerRoutes:97`/`sweepResidualRoutes:132`/`clearLedger:85`）、`fakeip_nat/route_mark.go`（目的地址打标分流（仅非 tun）：`verifyMarkRouting:246`/`reportMarkRouting:266`/`parseMarkTable:290`，`markRoutingEnabled:44`/`markActiveNow:43`/`ensureMarkTable:69`（集合 `real_ipv4` + `mark_prerouting`/`mark_output` 两条链）/`setupMarkRouting:129`（专用表 default + `ip rule fwmark`）/`markRealIP:190`/`cleanupMarkRouting:204`）；`fakeip_nat/tun.go:31`（tun 设备/段首地址（掩码取自 `ipv4_range`）/connected 路由）、`fakeip_nat/tunstack.go:93`（gVisor netstack 终止 TCP/UDP，`precheck:171`（TTL≤1 回 time exceeded，源地址经 `answerSource` 虚拟化）/`relayTCP`/`relayUDP:312`/`realTarget:508`）、`fakeip_nat/tunio.go`（平台无关读写泵）、`fakeip_nat/tuncmd.go`（linux/bsd/windows 命令计划）、`fakeip_nat/tunio_linux.go`（`/dev/net/tun` + TUNSETIFF）、`fakeip_nat/tunio_darwin.go`（utun 控制套接字）、`fakeip_nat/tunio_freebsd.go`（`/dev/tun`）、`fakeip_nat/tunio_windows.go`（Wintun + netsh）、`fakeip_nat/tun_icmp.go`（ICMP echo 双模式（代理本地合成 / 直连 raw 转发）、ICMP 错误转发与 hop 虚拟化、逐跳探测、hop 虚拟地址与 PTR：`startICMPRelay:251`/`forwardICMPEcho:881`/`answerEchoLocally:942`/`hopSource:399`/`probeHop:661`/`probeReply:706`/`hopFakeFor:513`/`hopOf:592`）、`fakeip_nat/bind_socket_linux.go`/`bind_socket_darwin.go`/`bind_socket_other.go`（raw ICMP 与探针 socket 绑定 `next_hop_dev`：`bindSocketToDevice`）、`fakeip_nat/icmpraw_linux.go`/`icmpraw_bsd.go`/`icmpraw_other.go`（raw ICMP socket 平台打开方式）、`fakeip_nat/packet.go:46`（IPv4 解析/改写/校验和，`buildICMPError:257`）、`fakeip_nat/flow.go:217`（假 IP→真实 IP 双向改写 + 连接映射）、`egress.go:48`（socks5/http/trojan 出站；UDP 分支 `dialUDP:302`/`:495`）、`fakeip_nat/egress_proxy_addr.go`（ATYP 地址编解码，socks5/trojan 共用）、`fakeip_nat/egress_socks5_udp.go`（RFC 1928 UDP ASSOCIATE + `socks5UDPConn`）、`fakeip_nat/egress_trojan_udp.go`（udp-associate 请求行 + 长度前缀数据帧）、`fakeip_nat/record_retention.go`（`record_ttl` 过期清理：`startRecordRetention:40`/`sweepRecords:95`）、`fakeip_nat/tun_snat.go`（`tunSNATPlan:24`）、`fakeip_nat/tun_snat_linux.go`（nft masquerade 安装/卸载）、`fakeip_nat/tun_snat_darwin.go`（隐式 SNAT 说明） |
| RADIUS 认证 / 记账 / 账号表 | `radius/radius_server.go:114`（`handleAccess`）、`:176`（`handleAccounting`）、`:207`（`reply`）；`radius_packet.go:160`（响应认证符）、`:172`（请求认证符）、`:182`（`User-Password` 解码）；`radius_store.go:112`（PBKDF2）、`:283`（记账落库）；`radius.go:121`（`Init`） |
| 答案里出现 IP 时回调外部脚本 | `exec_script/exec_script.go:97-131` |
| 客户端限速 / 坏 IP 观察 | `client_limiter/client_limiter.go:72-85`、`pkg/ip_observer/bad_ip_observer.go:100+` |
| 指标 / pprof / 插件 HTTP API | `mosdns.go:78-83`、`register.go:202-204`、`mosdns.go:156-158` |
| 系统服务安装 | `coremain/service.go`、`run.go:73-86` |
| CLI 子命令（probe / v2dat / config）| `tools/init.go:27-55` |

---

## 7. 配置装配细节

### 7.1 顶层结构（`config.go:28-38`）

```yaml
log:            # mlog.LogConfig: level / file / err_file / info_file
include: []     # 子配置路径
data_providers: # tag / file / auto_reload
plugins:        # tag / type / args
servers:        # exec / timeout / listeners[]
api:            # http
security:       # bad_ip_observer
```

### 7.2 监听器字段（`config.go:60-80`）

| 字段 | 用于 | 备注 |
|---|---|---|
| `protocol` | `""`/`udp`、`tcp`、`dot`/`tls`、`doh`/`https`、`http` | `http` 走 **Unix socket**，不监听 TCP |
| `addr` | host:port | 必填 |
| `cert` / `key` | dot、doh | |
| `url_path` | doh/http | 空 = 任意路径 |
| `get_user_ip_from_header` | doh/http | 从头部取客户端 IP |
| `proxy_protocol` | tcp/dot/doh/http | 要求对端发 PROXY protocol |
| `Unix` | tcp / http | **无 yaml tag**，按字段名匹配 |
| `idle_timeout` | tcp/dot/doh | 秒 |

> `coremain/server.go:53` 把 Unix socket 路径硬编码成 `/tmp/go-unix-socket`，**多个 `http`/`Unix` 监听器会抢同一个文件**。

### 7.3 include 合并顺序（`run.go:144-184`）

- 先递归读子配置，再把子配置的 `data_providers` / `plugins` / `servers` **放在主配置前面**（`:175-182`）。
- 也就是说：**子配置先初始化，主配置后初始化**；同名 tag 会在装配阶段报 `duplicated plugin tag`（`mosdns.go:143-145`）。
- 深度上限 8 层（`:146-148`），并做绝对路径环检测（`:155-158`）。

### 7.4 解码严格性（`run.go:138-142`）

- `ErrorUnused = true`：配置里写了结构体没有的字段 → 直接失败。
- `TagName = "yaml"`，`WeaklyTypedInput = true`：数字/字符串可以互相弱转。

### 7.5 装配期会被「静默跳过」的情况

| 情况 | 位置 | 表现 |
|---|---|---|
| `data_providers[].tag` 为空 | `mosdns.go:113-115` | 该 provider 被忽略，不报错 |
| `plugins[].tag` 或 `type` 为空 | `mosdns.go:140-142` | 该插件被忽略，不报错 |
| 预置插件重复注册 | `register.go:139-149` | **panic** |
| 插件 type 重复注册 | `register.go:57-60` | **panic** |

---

## 8. 影响面速查

| 你要改的东西 | 会牵动 |
|---|---|
| `qCtx` 增删字段（`pkg/query_context`）| 所有插件 + `parallel` 的 `Copy()` + `EntryHandler` |
| `Executable` 签名（`iface.go`）| 所有 executable 插件 + 4 类结构节点 + `cache.when_hit` |
| `register.go` 的注册/解码逻辑 | 全部 24 个可配置 type 的 args 解析 |
| `Config` / `ServerListenerConfig` | 所有用户 YAML（因为 `ErrorUnused=true`，加字段不会坏事，删/改字段会）|
| `coremain/server.go` 协议 switch | 新增协议要同步 `pkg/server` + 文档 |
| `enabled_plugin.go` | 整份启用清单；漏加 = 配置报 type 不存在 |
| `pkg/data_provider` 接口 | `domain`/`netlist` 加载助手、`hosts`、`redirect` 的热重载行为 |
| `pkg/cache` 的 `Backend` 接口 | `cache` 与 `reverse_lookup` 两个插件、两种后端 |

---

## 9. 已知坑（每条都有代码依据）

1. **注释与实现不一致**：`entry_handler.go:94` 注释写「无响应返回 REFUSED」，实际 `:118-122` 返回的是 `RcodeServerFailure`。排查客户端收到 SERVFAIL 时别被注释带跑。
2. **「不回包」其实是 SERVFAIL**：`_drop_response` 走的是 `blackhole.go:157-158`（`SetResponse(nil)`）且**仍会继续执行后续节点**（`:102-105`）；如果整条链最后都没有响应，入口统一兜底 SERVFAIL。想真正在链中间停住请用 `_return`（`sequence.go:79-81`）。
2. **预置专用插件没有 type**：`misc_optm`（`misc.go:33` 有常量但从未 `RegNewPluginFunc`）、`query_summary`（`query_summary.go:36`）、`padding`（`padding.go:34-42`）都只注册了预置 tag。写 `type: misc_optm` 会直接报 `plugin type misc_optm not defined`。
3. **所谓「空 tag 自动忽略」**：`mosdns.go:140-142` 对 `tag`/`type` 为空是 `continue`，配置写错不会报错，只会「插件悄悄没生效」。
4. **非 linux 上 `ipset` / `nftset` 是空壳**：`ipset_other.go:35-42`、`nftset_other.go:36-43` 只 `return ExecChainNode(...)`。在 macOS 上配置能过、启动不报错、但**一条规则都不会写**。
5. **`http` 协议不是 TCP 端口**：它监听 Unix socket `/tmp/go-unix-socket`（`server.go:53`、`:132-140`）；`ServerListenerConfig.Unix` 又没有 yaml tag（`config.go:78`），容易配了不生效。
6. **`fast_forward` 与 `forward` 不是同一套上游实现**：前者用 `pkg/upstream.NewUpstream` + `bundled_upstream.ExchangeParallel`（最快者胜，`fast_forward.go:187`）；后者用 `upstream.AddressToUpstream` 顺序兜底（`forward.go:103`）。参数名也不同（`upstream.addr` vs `upstream_config` 风格）。
7. **`udpme://` 是定制协议**：只在 `fast_forward` 里识别（`fast_forward.go:106-113`），`forward` 不支持。
8. **`fakeip_nat` 会改写答案并落库**：AAAA 直接返回空响应且**不再走 `next`**（`fakeip_nat.go:256-261`）；A 记录命中后替换成假 IP（`:292-306`）；数据面同步是 **goroutine 异步**执行（`:290`、`:416-453`），失败只打日志。默认由插件自己建 `fakeip_<prefix>` nft 表、探测候选真实 IP、写 host route 并做 CIDR 聚合（`nat.go`）；`use_tun: true` 时改为把 `ipv4_range` 路由到 TUN 设备（`tun.go`），出口侧由 `tun_egress.go` 建专用路由表 + `ip rule ... to !<range>`，并在 Linux 装 `<prefix>_tun_snat` 的 masquerade。外部脚本回调已移除。改写失败（DB/分配错误）时**保留真实 IP 响应**，不会返回 SERVFAIL。 TUN 模式下 UDP 走 SNAT：出口拨号按真实 IP、回包改回 fake IP。ICMP echo 分两条路——**配了代理时本地合成 echo reply**（代理协议不承载 ICMP，转发只会超时；保留客户端 id/seq/payload，不依赖 raw socket），**没配代理时才用 raw socket 换成真实 IP 重发**（socket 与探针 socket 一起绑定 `next_hop_dev`）。TTL 1 由 `precheck` 当代本设备这一跳应答、源地址用 `hopFakeFor(段首)` 的替身（直接用段首会被收包主机按 martian source 丢弃）；TTL 2..30 的 UDP 探针触发独立探测 socket（同样 TTL 向真实 IP 再发一次），应答那一跳分配段内虚拟地址做回包源地址，PTR 回 `<真实IP>.<hop_name_suffix>`，视图保留 30s 并在查询时续期；真实路由器回的 time exceeded 同样按跳虚拟化，port/host unreachable 保留真实地址。
9. **`exec_script` 默认异步**：`async` 未显式设置时为 `true`（`exec_script.go:54-57`），主链不会等脚本；`dedup_ttl` 默认 300s（`:49-52`）。
10. **`parallel` 分支必须 Copy 上下文**：`context.go:47` 明确非并发安全，`asyncWait` 只取第一个有响应的结果（`utils.go:32-57`）。
11. **有 `if:` 就必须有对应 matcher**：写错 tag 名是**启动期**报错，不是运行期（`if_node.go:119-125`）。
12. **`ErrorUnused=true` 的双刃**：拼错字段名（如 `max_ttl` 写成 `maxttl`）会在启动时直接失败，不会默默用默认值。

---

## 10. 变更验证建议（现状口径）

| 改动 | 最小验证 |
|---|---|
| 新增/修改插件 | `go build ./...`；`go test ./plugin/...`（`enabled_plugin_test.go` 会跑所有 `init()`）；`./mosdns start -c <cfg>` 看 `loading plugin` 日志 |
| 改配置结构 | 用带 `include` 的配置跑一次，确认合并顺序与 `ErrorUnused` 行为 |
| 改链路语义 | 用 `tools/probe` 的三条子命令（conn reuse / idle timeout / pipeline）配合真实上游观察 |
| 改 `fakeip_nat` / `exec_script` | NAT 模式看 `nft list map ip fakeip_<prefix> dnat_map` 与 `ip route` 目标表；TUN 模式看 `ip route show <ipv4_range>` 是否落到 tun 设备且带 `src <段首>`、`ip rule show` 是否有 `to !<range>`、`nft list table ip <prefix>_tun_snat` 是否有 masquerade、`ip addr show <tun_dev>` 是否为段首地址；代理是否生效看启动日志 `proxy egress ready` / `falling back to direct egress`；`traceroute 198.18.0.8` 看每跳是否是 `198.19.255.x` + `<真实IP>.<后缀>` 主机名、`dig -x <虚拟地址>` 第二次应 NXDOMAIN、`ping 198.18.0.8` 与 `netstat -s -p icmp` 的 bad length 计数；`go test ./plugin/executable/fakeip_nat/` |
