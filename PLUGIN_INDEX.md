# mosdns-v4 插件功能索引

> 覆盖 `plugin/` 下 **29 个插件目录**（27 executable + 2 matcher）、**26 个可配置 type**、**21 个预置 tag**。
> 行号对应当前工作树；「是否可配置」= 是否能在 `plugins[].type` 里写。
> 配套文档：`CODEBASE_MAP.md`（框架与链路）。
> 配套配置模板：`etc/mosdns/config.yaml`（顶部为最小可运行段，其下为 26 个可配置 type + 21 个预置 tag + 全部顶层字段的英文注释清单）。

---

## 1. 插件总表

| type | 可配置 | 目录 | 一句话行为 | 预置 tag |
|---|---|---|---|---|
| `sequence` | ✅ | `plugin/executable/sequence` | 把 YAML 的 `exec` 编译成执行链，是「入口」的常见载体 | `_return` |
| `forward` | ✅ | `plugin/executable/forward` | 顺序向多个上游转发，全部失败才失败 | — |
| `fast_forward` | ✅ | `plugin/executable/fast_forward` | 多上游并行，取最先返回的响应；支持 `udpme://` | — |
| `cache` | ✅ | `plugin/executable/cache` | 查询缓存（内存 / Redis），支持懒更新与 `when_hit` | `_default_cache` |
| `hosts` | ✅ | `plugin/executable/hosts` | hosts 文件语义，命中直接应答 | — |
| `arbitrary` | ✅ | `plugin/executable/arbitrary` | 内联 zone 文本，命中直接应答 | — |
| `redirect` | ✅ | `plugin/executable/redirect` | 把域名整条重写到另一个域名，再还原答案里的名字 | — |
| `blackhole` | ✅ | `plugin/executable/blackhole` | 返回指定 IP / 指定 RCode，或直接丢弃响应 | `_drop_response` `_new_empty_response` `_new_servfail_response` `_new_nxdomain_response` |
| `dual_selector` | ✅ | `plugin/executable/dual_selector` | A/AAAA 双查：若另一族有记录，则抑制本族查询 | `_prefer_ipv4` `_prefer_ipv6` |
| `ecs` | ✅ | `plugin/executable/ecs` | 给查询加 EDNS0 Client Subnet，回包时再剥掉 | `_no_ecs` |
| `edns0_filter` | ✅ | `plugin/executable/edns0_filter` | 按选项号保留/丢弃查询里的 EDNS0 option | `_edns0_filter_no_edns0` `_edns0_filter_ecs_only` |
| `bufsize` | ✅ | `plugin/executable/bufsize` | 收窄查询声明的 UDP 包大小（512–4096） | — |
| `ttl` | ✅ | `plugin/executable/ttl` | 对响应做 TTL 上限/下限裁剪 | — |
| `sleep` | ✅ | `plugin/executable/sleep` | 在链上等待指定毫秒 | `_sleep_500ms` |
| `marker` | ✅ | `plugin/executable/marker` | **双重身份**：执行时打标记，也能当 matcher 判断标记 | — |
| `metrics_collector` | ✅ | `plugin/executable/metrics_collector` | 记录该节点的查询数、错误数、并发数、响应耗时 | — |
| `client_limiter` | ✅ | `plugin/executable/client_limiter` | 按客户端 IP 限 QPS，超限回 REFUSED 并记入坏 IP | — |
| `ipset` | ✅ | `plugin/executable/ipset` | 把响应 IP 写入 ipset（**仅 linux 有效**） | — |
| `nftset` | ✅ | `plugin/executable/nftset` | 把响应 IP 写入 nftables set（**仅 linux 有效**） | — |
| `reverse_lookup` | ✅ | `plugin/executable/reverse_lookup` | 记录 域名↔IP 映射，可应答 PTR，并提供 HTTP 查询接口 | — |
| `fakeip_nat` | ✅ | `plugin/executable/fakeip_nat` | **定制**：A 记录改写成假 IP，落 SQLite；默认用内置 NAT（nftables DNAT + host route + CIDR 聚合），`use_tun` 可切到 TUN 数据面（TCP/UDP/ICMP 统一 SNAT，逐跳探测把 traceroute 全路径送回 tun） | — |
| `ocserv_ctl` | ✅ | `plugin/executable/ocserv_ctl` | **定制**：把 DNS 请求的源地址映射到 ocserv 登录用户（`occtl show users`），命中时给查询打标记 | — |
| `telegram_bot` | ✅ | `plugin/executable/telegram_bot` | **定制**：Telegram 长轮询管理 fakeip / ocserv / RADIUS 账号 / 配置 / 脚本，按角色下发权限 | — |
| `radius` | ✅ | `plugin/executable/radius` | **定制**：给 ocserv 当 RADIUS 服务端（PAP 认证 + RFC 2866 记账），账号存本机 SQLite，由 bot 的 `/user` 增删改 | — |
| `exec_script` | ✅ | `plugin/executable/exec_script` | **定制**：答案里出现 IP 时调外部脚本（默认异步 + TTL 去重） | — |
| `query_matcher` | ✅ | `plugin/matcher/query_matcher` | 按客户端 IP / ECS / 域名 / QType / QClass 判断 | `_qtype_A_AAAA` `_qtype_AAAA` `_query_edns0` |
| `response_matcher` | ✅ | `plugin/matcher/response_matcher` | 按 RCode / 答案 IP / CNAME 判断 | `_response_valid_answer` |
| `misc_optm` | ❌ | `plugin/executable/misc_optm` | 拦截异常查询、压 UDP 大小、洗牌 A/AAAA、清 padding | `_misc_optm` |
| `query_summary` | ❌ | `plugin/executable/query_summary` | 每条查询打一行摘要日志 | `_query_summary` |
| `padding` | ❌ | `plugin/executable/padding` | RFC 8467 padding（查询 128 / 响应 468 字节） | `_pad_query` `_enable_conditional_response_padding` `_enable_response_padding` |

---

## 2. 逐个插件卡片

### 2.1 `sequence` — 执行链编译器
- **文件**：`plugin/executable/sequence/sequence.go`
- **注册**：`:33` 类型；`:34` 预置 `_return`
- **参数**：`exec`（`interface{}`，可写字符串 tag / 字符串数组 / `if` / `parallel` / `load_balance` / `primary+secondary`）
- **行为**：`Init` 调 `executable_seq.BuildExecutableLogicTree`（`:54`）编译成链；`Exec` 先跑自己的链、**再跑外层的 `next`**（`:65-71`）
- **`_return`**：`Exec` 直接 `return nil`，不调 `next`（`:79-81`）→ 用它在链中间「到此为止」
- **注意**：编译期就会解析所有 tag，写错立刻启动失败；`sequence` 可以嵌套 `sequence`

```yaml
- tag: main_seq
  type: sequence
  args:
    exec:
      - _misc_optm
      - cache
      - if: "qtype_A_AAAA && !is_local"
        exec: [fast_forward]
        else_exec: [_return]
```

### 2.2 `forward` — 顺序多上游
- **文件**：`plugin/executable/forward/forward.go`
- **注册**：`:38`；**参数**（`:49-64`）：`upstream[]{addr, ip_addr, trusted(已废弃)}`、`timeout`、`insecure_skip_verify`、`bootstrap`
- **行为**：`Exec` → `exec`（`:125`）依次尝试上游；全部失败才返回 error；成功后仍会调 `next`
- **注意**：`trusted` 字段保留但无效果（`:61-63` 注释）

### 2.3 `fast_forward` — 并行取最快
- **文件**：`plugin/executable/fast_forward/fast_forward.go`（`udpme.go` 为定制协议）
- **注册**：`:43`；**参数**（`:56-75`）：`upstream[]{addr, dial_addr, trusted, socks5, so_mark, bind_to_device, idle_timeout, max_conns, enable_pipeline, enable_http3, bootstrap, insecure_skip_verify}`、`ca[]`
- **行为**：构造时把**第一个上游强制设为 trusted**（`:145-147`）；`Exec` → `bundled_upstream.ExchangeParallel`（`:187`），谁先回包用谁
- **定制点**：`addr` 以 `udpme://` 开头时走内置 `udpmeUpstream`（`:106-113`），仅此插件支持

### 2.4 `cache` — 查询缓存
- **文件**：`plugin/executable/cache/cache.go`
- **注册**：`:47`；预置 `_default_cache`（`:49`，等价 `Args{}`）
- **参数**（`:61-70`）：`size`、`redis`、`redis_timeout`、`lazy_cache_ttl`、`lazy_cache_reply_ttl`（≤0 → 5s，`:114-116`）、`cache_everything`、`compress_resp`（snappy）、`when_hit`（可执行 tag）
- **行为**（`:156-197`）：
  - 只有「单问题、且无 Answer/Ns/Extra」的简单查询才缓存（`:202-203`），除非 `cache_everything`
  - 命中 → 改 ID、`SetResponse`，若配了 `when_hit` 则执行它（`:176-185`）
  - 过期命中 → 记 `lazy_hit_total`，并后台刷新；同一个 msgKey 用 `singleflight` 去重（`:172-175`、`:267-268`）
  - 未命中 → 走 `next`，拿到响应后落缓存（`:188-196`）
- **指标**：`query_total`、`hit_total`、`lazy_hit_total`、`cache_size`（`:133-152`，前缀 `plugin_<tag>_`）
- **注意**：`_default_cache` 的 `size=0` → 内存缓存退化为 **64 shard × 16 = 约 1024 条**（`pkg/cache/mem_cache/mem_cache.go:52-56`）

### 2.5 `hosts`
- **文件**：`plugin/executable/hosts/hosts.go`；注册 `:35`；参数 `hosts[]`（文件路径，走 data_provider 热重载）
- **行为**：默认 `MatcherFull`（`:55`、`:63`）；`Exec` 用 `LookupMsg` 命中就**短路返回**（`:79-87`）

### 2.6 `arbitrary` — 内联 zone
- **文件**：`plugin/executable/arbitrary/arbitrary.go`；注册 `:35`；参数 `rr[]`（每项是一段 zone 文本）
- **行为**：用 `pkg/zone_file` 建索引（`:57-71`），命中 `Reply` 就短路（`:49-55`）
- **注意**：`Init` 里 TODO 明确写了暂不支持 data_provider（`:61`），规则只能内联、不能热重载

### 2.7 `redirect` — 域名重写
- **文件**：`plugin/executable/redirect/redirect.go`；注册 `:38`；参数 `rule[]`（每条必须两段：`原域名 目标域名`，`:57-63`）
- **行为**：命中后改 `Question[0].Name`（`:101`），跑 `next`，再把响应里 Question 与 Answer 的名字还原（`:102-113`）
- **注意**：只改域名、不改 QType；`rule` 支持 data_provider 热重载（`:65-80`）

### 2.8 `blackhole` — 黑洞 / 指定应答
- **文件**：`plugin/executable/blackhole/blackhole.go`；注册 `:36`；参数（`:62-66`）：`ipv4[]`、`ipv6[]`、`rcode`
- **行为**（`:107-158`）：A/AAAA 有配 IP → 直接答这些 IP（TTL 硬编码 3600）；否则 `rcode >= 0` 用 `GenEmptyReply` 造空响应，`rcode < 0` 则 `SetResponse(nil)`（`:153-158`）
- **预置**（`:38-49`）：`_drop_response`(rcode=-1)、`_new_empty_response`(0)、`_new_servfail_response`(2)、`_new_nxdomain_response`(3)
- **注意**：`Exec` 永远不返回 error，且**无条件会调 `next`**（`:102-105`）。所以 `_drop_response` **不是丢包**：它只是把响应置空然后继续走链；若最终仍无响应，入口会兜底成 **SERVFAIL**（`pkg/server/dns_handler/entry_handler.go:118-122`）。真正想「到此为止」请用 `_return`。

### 2.9 `dual_selector` — A/AAAA 互斥
- **文件**：`plugin/executable/dual_selector/dual_selector.go`；注册 `:45`；预置 `_prefer_ipv4`(mode 0)/`_prefer_ipv6`(mode 1)（`:46-51`）
- **参数**：`mode`、`wait_timeout`（毫秒；默认 250ms，`defaultWaitTimeout` 在 `:40`）
- **行为**（`:75-158`）：只处理纯 A 或纯 AAAA 查询；**并行发一条另一族查询**（`:88-120`）：
  - 另一族有记录 → 立即回「本族空答案」（`:134-137`、`:144-147`）
  - 另一族没有 → 采用原查询结果（`:148-150`）
  - 等参考查询超时 → 也采用原查询结果（`:151-155`）
- **注意**：两个分支都用 `qCtx.Copy()`（`:88`、`:124`），因为 `qCtx` 非并发安全

### 2.10 `ecs` — Client Subnet
- **文件**：`plugin/executable/ecs/ecs.go`；注册 `:37`；预置 `_no_ecs`（`:39`，等价「查询和响应都剥掉 ECS」，`:205-217`）
- **参数**（`:46-61`）：`auto`（用客户端地址）、`force_overwrite`、`mask4`(24)、`mask6`(48)、`ipv4`、`ipv6`
- **行为**（`:122-139`）：加 ECS → `next` → 回包时按情况剥：升级了 EDNS0 就整体移除 EDNS0，只是新增 ECS 就只删 ECS
- **注意**：`auto=true` 时预置 IP 不生效（`:47-49` 注释 + `:155`）

### 2.11 `edns0_filter`
- **文件**：`plugin/executable/edns0_filter/filter.go`；注册 `:34`；预置 `_edns0_filter_no_edns0`（`:35`，`NoEDNS`）、`_edns0_filter_ecs_only`（`:38`，仅保留 ECS）
- **参数**（`:43-49`）：`no_edns`、`accept[]`、`discard[]`；优先级 `NoEDNS > accept > discard`（`:44-46`）
- **行为**：只改**查询**的 EDNS0 option（`applyFilter` `:91-126`），不改响应
- **注意**：`accept` / `discard` 都不填时 = 「删掉所有 option 但保留 EDNS0 RR」（`default` 分支 `:119-125`）

### 2.12 `bufsize`
- **文件**：`plugin/executable/bufsize/bufsize.go`；注册 `:32`；参数 `size`（512–4096，超出即夹紧，`:46-54`）
- **行为**：只收窄查询里的 `UDPSize`（`:56-66`）

### 2.13 `ttl`
- **文件**：`plugin/executable/ttl/ttl.go`；注册 `:35`；参数 `maximum_ttl`、`minimal_ttl`
- **行为**：**后置**处理，只改 `qCtx.R()`（`:61-71`）；两个都为 0 时等于什么都不做

### 2.14 `sleep`
- **文件**：`plugin/executable/sleep/sleep.go`；注册 `:36`；预置 `_sleep_500ms`（`:40`）；参数 `duration`（毫秒）
- **行为**：从池里取 timer 等 `duration`，`ctx` 取消会提前返回（`:60-70`）

### 2.15 `marker` — 双重身份
- **文件**：`plugin/executable/marker/marker.go`；注册 `:32`
- **行为**：`Exec` 给 `qCtx` 打一个全局唯一 mark（`:50-53`）；`Match` 判断该 mark 是否存在（`:43-45`）
- **用法**：同一个 tag 既能出现在 `exec` 里当一步，也能出现在 `if` 表达式里当条件
- **注意**：同时声明了 `ExecutablePlugin` 与 `MatcherPlugin`（`:35-36`），所以会被同时放进 `execs` 和 `matchers`

```yaml
- tag: mark_oversea
  type: marker
# 用法：
# exec: [mark_oversea, ...]
# if: "mark_oversea"
```

### 2.16 `metrics_collector`
- **文件**：`plugin/executable/metrics_collector/collector.go`；注册 `:34`；**无参数**
- **行为**（`:75-89`）：`thread` gauge 进出、`query_total`、`err_total`、`response_latency` 直方图（毫秒）
- **注意**：指标名带 `plugin_<tag>_` 前缀（`register.go:202-204`），因此可以多处放置、互不冲突

### 2.17 `client_limiter`
- **文件**：`plugin/executable/client_limiter/client_limiter.go`；注册 `:36`
- **参数**：`max_qps`、`v4_mask`(32)、`v6_mask`(48)
- **行为**（`:72-85`）：客户端地址无效直接放过；超限 → `Refused` 且 `GetBadIPObserver().Observe(addr)`
- **注意**：5s 一次的 GC 循环（`:94-105`），`Close` 只关通知 chan

### 2.18 `ipset`（仅 linux 写入）
- **文件**：`plugin/executable/ipset/{ipset.go,ipset_linux.go,ipset_other.go}`；注册 `:29`；参数 `set_name4/set_name6`、`mask4`(24)、`mask6`(32)
- **行为**：linux 下**后置**把响应里的 A/AAAA 写进 ipset（`:64-112`），失败只打 warn
- **非 linux**：`ipset_other.go:39-41` 只透传 `next`，**不做任何事且不报错**

### 2.19 `nftset`（仅 linux 写入）
- **文件**：`plugin/executable/nftset/{nftset.go,nftset_linux.go,nftset_other.go}`；注册 `:29`
- **参数**（`:34-42`）：`table_family4/6`（`ip`/`ip6`/`inet`）、`table_name4/6`、`set_name4/6`、`mask4`(24)、`mask6`(32)
- **行为**（`:78-138`）：先把响应 IP 收集成 `SetIPElem`，再批量写 nftables；失败只打 warn
- **注意**：任一组三元组（family/table/set）不全就不建该族 handler（`:51-70`）；非 linux 同样为空壳

### 2.20 `reverse_lookup`
- **文件**：`plugin/executable/reverse_lookup/reverse_lookup.go`；注册 `:45`
- **参数**（`:50-55`）：`size`(64k)、`redis`、`handle_ptr`、`ttl`(1800)
- **行为**（`:106-118`）：查询是 PTR 且 `handle_ptr` → 用缓存反查并**直接应答**；否则跑 `next`，再用响应里的 IP 建映射
- **HTTP API**：实现 `ServeHTTP`（`:124`），自动挂在 `/plugins/<tag>/`，`?ip=x.x.x.x` 查询
- **注意**：这是全仓唯一走插件 HTTP API 的插件

### 2.21 `fakeip_nat`（定制）
- **文件**：`plugin/executable/fakeip_nat/fakeip_nat.go`（注册 `:37`）、`nat.go`（NAT 数据面）、`tun.go`（TUN 设备/路由/首地址保留）、`tunstack.go`（用户态栈 TCP/UDP 终止与出口；`relayUDP :263` 选出口并把逐跳探针分流出去）、`tun_icmp.go`（ICMP echo / ICMP 错误转发、逐跳探测、hop 虚拟地址表与 PTR 应答）、`icmpraw_linux.go`/`icmpraw_bsd.go`/`icmpraw_other.go`（raw ICMP socket 的平台打开方式）、`tunio.go`（与平台无关的读写泵）、`tuncmd.go`（各平台命令计划）、`tunio_linux.go`/`tunio_darwin.go`/`tunio_freebsd.go`/`tunio_windows.go`（按 `release.py` 目标分平台编译）、`tunio_bsd.go`（darwin/freebsd 共用 fd 设备）、`tunio_other.go`（其余平台占位）、`egress.go`（TUN 出站代理）、`egress_bind_linux.go`/`egress_bind_darwin.go`/`egress_bind_other.go`（出口 socket 绑定网卡）、`tun_egress.go`（TUN 直连出口：独立路由表/源地址绑定/UDP 出口选择）、`tun_egress_linux.go`/`tun_egress_darwin.go`/`tun_egress_other.go`（按平台安装）、`route_ledger.go`（受管路由账本：记录写入的每条前缀，停止/启动时按账本清理，扫描兜底）、`bind_socket_linux.go`/`bind_socket_darwin.go`/`bind_socket_other.go`（raw ICMP 与逐跳探针 socket 绑定 `next_hop_dev`）、`packet.go`（IPv4 包解析/改写/校验和/ICMP 错误构造）、`flow.go`（fake IP 反查 + 连接映射 + 双向改写）、`mapping_runtime.go`（运行时 domain↔fake IP 表：启动从 SQLite 恢复，NAT 模式与 nft map 对账）
- **参数**（`fakeip_nat.go:44-86`）：`db_path`(`/config/mosdns/fakeip.db`)、`table_prefix`(`default`)、`ipv4_range`(`198.18.0.0/15`)、`ttl`(60)、`next_hop`、`next_hop_dev`、`route_table`(`main`)、`route_aggregation`(true)、`route_mark`(0=关闭；非 0 改走目的地址打标分流)、`route_rule_priority`(1000，打标模式那条 ip rule 的优先级，1..32766)、`tun_route_table`(`100`，TUN 直连专用表)；`use_tun`(false)、`tun_dev`(空=自动申请 mth0/mth1…)、`proxy`(空=直连)、`proxy_insecure`(false)、`hop_name_suffix`（逐跳 PTR 后缀，单标签；空则复用 `table_prefix` 并把 `_` 换成 `-`，非法值启动即报错）、`record_ttl`（映射/真实 IP 记录保留期，空=168h，`"0"`=关闭，负值/无单位/非法值启动即报错）。`script` 已废弃（保留字段仅为兼容旧配置，告警后忽略）
- **初始化**（`Init :167`）：校验 `table_prefix`与 `ipv4_range`（必须是 IPv4、至少 2 个可用地址，`:169-183`）→ 预计算 `maxHosts` → 建 SQLite（WAL + busy_timeout，**连接池固定 1**）→ 建 `<prefix>_mapping` / `<prefix>_real_ips` + 索引 → `Ping` 探活→ 出站代理解析与探测→ `use_tun` 时 `setupTun` + `startTunDataPath`→ 挂 `safe_close`；`Close :480` 先 `stopTunDataPath` 再关库
- **行为**（`Exec :494`）：
  1. 查询有 AAAA → **直接回空答案，不再走 `next`**（`:417-423`）
  2. 若还没有响应，先跑 `next`（`:426-433`）
  3. A 查询且响应里有 A 记录 → `recordAndAllocate`（`:438-479`）→ 异步派发数据面任务（`dispatchNAT :594-606`）→ 用假 IP 重写答案（`:456-475`）
- **保留期**（`record_retention.go`）：`startRecordRetention :40` 启动后 5s 先扫一次，之后按 `min(record_ttl,1h)`（下限 1min）周期执行；`sweepRecords :95` 持有分配锁、单事务删除过期映射与陈旧真实 IP，`last_seen` 取内存 touch 与库内 `last_seen`/`created_at` 的最大值，`pending` 行永不过期，**提交成功后**才 `runtime.remove` 释放地址。错误只告警不中断循环。
- **假 IP 分配算法**（`recordAndAllocate :626` + `nextFreeFakeIP :707`）：段首地址（`reservedFakeIP`）留给 tun 网卡，分配从 offset 2 起**线性扫描最低空闲地址**，跳过 `skip` 集合、`runtime.taken()` 与仍在 `hopViewTTL` 内的 traceroute hop；先 `INSERT ... ON CONFLICT DO NOTHING` 写 `pending` 再原子翻转（`UNIQUE constraint failed` 时 `isUniqueViolation` 判定后换下一个候选，最多 16 次；`RowsAffected()==0` 说明别的进程先翻转了该行，直接读其结果）。这样被 `record_ttl` 回收的低位地址可以重新分配；旧的 `allocateFakeIP :653` 只保留给测试使用
- **两种数据面**（异步执行、同域互斥、全局并发 8，`enqueueTask :722`）：
  - `use_tun: false`（默认）→ **内置 NAT** `nat.go`：建 `fakeip_<prefix>` 表（`dnat_map` + prerouting/forward/postrouting 三条链；postrouting 的 masquerade 条件是 `ct status dnat`，只改写被本表 DNAT 过的连接，不再按 `oifname` 一把抓，避免把整张网卡上的其它流量一起 SNAT）→ 查现有映射，可达就复用 → 候选 IP（参数优先，缺失回落 DB 最近 15 条）→ 并发探测 443/80 + ping → `nft add element` → 写 `/32` host route（同时记进 `route_ledger.go` 的账本）→ 严格 CIDR 聚合（`syncNAT :71`、`ensureNFTTable :181`（表已存在时先用 `nftTableMatchesConfig` 校验形状：postrouting 必须是 `ct status dnat`、DNAT/drop/mss 与配置一致，否则删表重建）、`probeReachable :690`、`collapsePrefixes :822`）；`aggregateManagedRoutes :300` 每 30s 一次：先记原始列表 → 剔除不可聚合 → 先加聚合网段 → 再按原始列表删除 → `pruneManagedRoutes :332` 删掉不再覆盖任何已知真实 IP 的块；`cleanupDataPath :462` 先按账本删、再按已知真实 IP 扫描兜底（扫描命中的前缀须通过 `foreignRoute`：账本无记录且不是账本行折叠出的聚合块则跳过，避免删掉运维自建路由）、最后 `nft delete table ip <prefix>`
  - `route_mark`（目的地址打标分流，`route_mark.go`，仅 Linux、`route_table` 不得为 `main`；tun 模式下仅 `realip` 生效）：`ensureMarkTable :75` 在 `fakeip_<prefix>` 里重建集合 `real_ipv4`（`type ipv4_addr; flags timeout; timeout 1h`）与 `mark_prerouting`（prerouting priority 0，排在 DNAT 的 -100 之后）、`mark_output`（`type route hook output`，改 mark 后重跑寻路）两条链，各挂 `ip daddr @real_ipv4 ip saddr != <ipv4_range> meta mark set <route_mark>`（源地址条件排除插件自己的拨号 socket）；`setupMarkRouting :141` 再 `ip route replace default [via hop] [dev dev] table <route_table>`（非 tun：hop/dev 留空取缓存的系统默认路由；tun + realip：固定 `dev <tun_dev>`，把标记流量路由进设备）与 `ip rule del/add fwmark <mark> lookup <table> prio <prio>`（`markRuleArgs :205` 统一 add/del 形状），成功后置 `markActive`；此后 `applyHostRoute :252` 只走 `markRealIP :217`（`nft add element`，失败 Warn 后回落 host route），`aggregateManagedRoutes :283` 与 `startRouteAggregation :757` 在打标模式下早退；`cleanupMarkRouting :231` 删 rule、删表内 default，`cleanupDataPath` 无条件下 `nft delete table`（tun 模式同样删，清掉上次非 tun 运行遗留的表；`cleanupStaleNFTTable :894` 在 tun 启动前先做同一件事）
  - `startupSweep`：`sweepResidualRoutes`（`route_ledger.go:132`）在数据面就绪后先清账本、再扫描仍然覆盖已知真实 IP 的 host route；小于 `/8` 的前缀才允许删除（`manageablePrefix :570`），避免误删运维自己的宽路由
  - `use_tun: true` → **TUN**（`tun.go`）：`ip link show` 判存在，缺失则 `ip tuntap add ... mode tun`（名字从 `mth0` 起取第一个空闲编号，上次遗留且带段首地址的设备会复用）→ `ip link set ... up` → `ip addr replace <段首>/<ipv4_range 前缀>`（例如 `198.18.0.1/15`，内核据此自动生成 connected route `<ipv4_range> dev <tun> ... src <段首>`；只有范围是 `/32` 时才补 `ip route replace <ipv4_range> dev <tun> src <段首>`）→ `sysctl -w net.ipv6.conf.<tun>.disable_ipv6=1`（best effort，消除内核 MLD/DAD 噪音），不再写任何 nft 元素；设备申请失败只告警、不阻断启动
- **TUN 数据面（用户态栈，方案 A）**：`setupTun :53` 建设备/设地址/写整段路由后，`startTunDataPath :335` 用 `newTunStack :76` 建 gVisor netstack（`channel` 链路端点 + IPv4/TCP/UDP 协议 + `SetPromiscuousMode`/`SetSpoofing` + 默认路由回本网卡），`startStack :120` 挂 TCP/UDP forwarder；各平台实现同一组接口（先开设备再配置，因为 darwin/windows 的网卡只在句柄存在期间存在）：Linux 走 `TUNSETIFF`（`IFF_TUN|IFF_NO_PI`）+ `ip tuntap/link/addr/route`；darwin 走 `AF_SYSTEM`+`com.apple.net.utun_control` 的 utun 套接字（4 字节 AF 头在读写时剥离/补齐；utun 编号由内核分配，connect 固定传 unit 0，显式 `tun_dev` 只在该设备不存在时才降级为自动分配，设备已存在则直接报错，因为那是别的进程的网卡）+ `ifconfig`/`route`（点对点接口，`ifconfig` 必须给对端地址：`inet <addr> <addr> netmask 255.255.255.255`）；FreeBSD 走 `/dev/tun<N>` + `TUNSIFHEAD`/`TUNSIFMODE` + `ifconfig`/`route`；Windows 走 Wintun 适配器（`wintun.dll`，需管理员）+ `netsh`。共享的读写泵把设备包按归属过滤（`ownsTunDestination`：假段 / 设备地址 / 本次运行记录过的真实 IP，其余丢弃）后 `inject :97` 进栈、把栈输出的包写回设备（`readFromTun :126`/`writeToTun :164`），1 秒读超时用于感知关闭；`stopTunDataPath :369` 关 ctx + 关链路端点。`relayTCP :139` 用 `CreateEndpoint` 终止连接后按目标拨号，`relayUDP :189` 同样终止后走 `dialUDP`：直连出口由 egress 拨号（带源地址与网卡绑定），socks5/trojan 出口可承载 UDP，只有 http/https 回落直连；`dialTarget :267` 决定出口：**代理生效 → `domain:port`**（域名交给代理解析），**否则 → 最近真实 IP:port**；`realTarget :298` 是 UDP 专用（永远用真实 IP，fake IP 只在本机与栈之间使用）。未覆盖平台由 `tunio_other.go` 占位，`use_tun` 返回错误并告警
- **主机语义（TUN）**：`newTunStack :76` 把段首地址以 `/32` `AddProtocolAddress` 到栈，段首是本地地址，`ping <段首>` 由 IPv4 协议自己回 echo reply；入栈前 `precheck` 判断：目的为段首的 UDP 探针回 `ICMP port unreachable`（`buildICMPError :257`），TTL ≤ 1 且目的不是段首的包回 `ICMP time exceeded`；查不到真实 IP 的假 IP 不回包，客户端看到超时。`relayTCP` 先解析目标再建 endpoint：段首无人监听 → `Complete(true)` 回 RST，未知假 IP → 不回包
- **UDP / ICMP SNAT（`tun_icmp.go`，`use_tun` 时随栈启动）**：`startICMPRelay :251` 打开 raw ICMP socket（配置了 `next_hop_dev` 时用 `bindConnToDevice :788` 绑网卡，平台不支持则保持系统路由并打一条 Info）后台读取；`tunio` 读循环顺序是 `describePacket` → `precheck`（TTL≤1 回 time exceeded、发往段首的 UDP 回 port unreachable）→ `rememberClientQuote`（仅 UDP，按 `quoteKey{src,dst,sport,dport}` 记客户端原包与 TTL，10s）→ `handleICMPEcho`（命中短路，不进栈）→ `inject`
  - **echo**：`handleICMPEcho :853` 只接受目的为 fake IP 的 echo request；`forwardICMPEcho :881` 先解析真实 IP（未映射则静默丢弃），**配了代理时**走 `answerEchoLocally :942` 本地合成 echo reply（代理协议不承载 ICMP，转发必然超时；保留客户端 id/seq/payload，不需要 raw socket），**没有代理时**才用 raw socket 以真实 IP 为源重发、改写 id/seq 后登记 `echoes`（`echoPendingTTL=10s`），`relayEchoReply :331` 按表项把回包源地址改回 fake IP 注入 tun
  - **ICMP 错误**：`relayICMPError :363` 处理真实路由器回的 port unreachable / time exceeded，按引用里的传输头（UDP 源端口或 echo id）定位客户端；**time exceeded 经 `hopSource :399` 按跳虚拟化**（源地址换成段内替身、PTR 返回真实路由器地址），port/host unreachable 保留真实源地址；出口 socket 报错时按 errno 合成同样的错误（`ECONNREFUSED→3/3`、`EHOSTUNREACH→3/1`、`ENETUNREACH→3/0`），raw socket 不可用也照发，客户端不超时
  - **引用边界**：`buildICMPError :257` 的引用必须是客户端实际发出的 `IP 头 + 8 字节传输头`（`ttlQuoteLen`）；`len(orig) < ihl+ttlQuoteLen` 直接放弃，否则 macOS/XNU `icmp_input` 按 `bad length` 丢弃——这是早期 traceroute 全 `*` 的根因
  - **第 1 跳**：`tunStack.precheck`（`tunstack.go:171`）对 TTL≤1 的包回 time exceeded，源地址用 `answerSource` 换成 `hopFakeFor(段首)` 的替身地址——直接用段首会收包主机按 martian source 丢弃，traceroute 只能显示 `*`；替身地址的 PTR 返回 `198.18.0.1.<hop_name_suffix>`，第 1 跳显示 `198.18.0.1.mosdns (198.19.x.y)`
  - **逐跳探测**：`shouldProbe :651` 让 TTL 2..30 的 UDP 探针不进 netstack 建流（TTL 1 已被 `precheck` 当作本设备这一跳）；`probeHop :661` 用 `listenProbeSocket :758`（未连接 UDP + `IP_TTL` + `bindSocketToDevice` 绑 `next_hop_dev`）向真实 IP 发 `probePayloadSz=32` 字节探针，`probes` 表以探测 socket 本地端口为键记客户端/引用/`deadline`（`hopProbeTimeout=1200ms`），应答、超时、5s 清扫都会删条目
  - **hop 虚拟地址**：`hopFakeFor :513` 在段尾一侧取段内地址：起点由真实地址的 FNV-1a 哈希决定（`hopOffsetFor :556`），冲突向低位顺延，因此同一真实跳在多轮 traceroute 里稳定拿到同一虚拟地址（`runtime.taken()` 跳过已分配的 fake IP，`hopByReal` 在视图存活期内复用，`hopViewMax=256`）；`probeReply :706` 用该地址做 ICMP time exceeded 的源地址、客户端原探针做引用，所有探测回包都落在 `ipv4_range` 内、必进 tun
  - **PTR 与销毁**：`Exec` 的 PTR 分支用 `ptrAddr :627` 解析 `in-addr.arpa`，命中 `hopOf :592` 后直接回 `<真实地址>.<hop_name_suffix>.`，不走 `next`；`hopOf` **保留视图并在查询时续期**（traceroute 每跳连发多个探针、PTR 可能滞后），`sweepHops :608` 以 `hopViewTTL=30s` 兜底清理
- **运行时映射表**（`mapping_runtime.go`）：`runtime :267` 是 `<prefix>_mapping` 的内存镜像（domain↔fake IP 双向 + 防火墙独占地址的 reserved 标记）；`Init` 先 `restoreRuntimeMappings :116` 把存量关系全部载入（`pending` 行跳过，等首次分配），`use_tun: false` 时再 `reconcileFirewallMappings :148` 与 `fakeip_<prefix>` 的 `dnat_map` 双向对账：数据库有、防火墙缺 → 用最近真实 IP 重新 `nft add element`；防火墙有、数据库缺 → `reserve` 该假 IP 防止重复分配；`domainForFakeIP` 先查内存，未命中才回查 SQLite 并回填
- **记录保留（`record_retention.go`，`record_ttl` 配置项）**：默认 `168h`，`"0"` 关闭，负值/无单位/非法值在 `Init` 直接报错；`startRecordRetention :40` 先等 5 秒扫一次，之后按 `min(record_ttl, 1h)`（不低于 1 分钟）周期跑 `sweepRecords :95`。判定过期取**内存 touch、库内 `last_seen`、`created_at` 三者最大值**与 cutoff 比较（老库首次运行不会被整表误删），`pending` 行永不过期；单个事务内删除过期 mapping、回写被 touch 过的 `last_seen`、清理 `real_ips`，**提交成功后才** `runtime.remove` 释放地址，Debug 日志 `retention sweep done` 带 `scanned/expired/refreshed/real_ips_dropped/cutoff`
- **TUN 直连出口路由与 SNAT**（`tun_egress.go` + `tun_snat*.go`，无代理时生效）：`setupTunEgress :23` 在设备就绪后解析出站目标（显式 `next_hop`/`next_hop_dev`，缺 hop 时回落 `systemDefaultRoute`），Linux 用 `tunRoutePlan :141` 生成四条命令：`ip route replace default via <hop> dev <dev> table <tun_route_table>`、`ip rule del from <range> lookup <table>`（清旧版规则）、`ip rule del/add from <range> to !<range> lookup <table>`（打标启用时带 `prio <route_rule_priority-1>`，必须排在 `fwmark` 规则之前，否则栈自己开的 socket 会被打标回灌进设备；未打标时不带 prio，保持内核默认位置）。**`to !<range>` 是关键**：客户端发往 fake IP 的包源地址也是段首（出口网卡就是 tun），若只按 `from` 匹配会被拽进出口表、从物理网卡直出而绕过 tun；加上目标排除后，只有真正出公网的包才进专用表。`prepareDirectEgress` 把 `directEgress` 的 `local` 设为段首地址（先 `canBindAddress` 试绑 TCP+UDP，失败只告警）并设置 `dev`（Linux `SO_BINDTODEVICE`、darwin `IP_BOUND_IF`）。随后 `installTunSNAT`：Linux 在独立 nft 表 `<prefix>_tun_snat` 里装 `add rule ip <t> postrouting oifname <dev> ip saddr <range> masquerade`（`tunSNATPlan :24`；选路先于改写，先按段首命中 rule 选中网关，再在 postrouting 把源改成宿主地址），表名与 NAT 数据面的 DNAT 表分开、互不删除；darwin 出口源地址本来就是宿主地址（等价改写后的状态），只打 Info 日志不动 pf。`Close` 时 `stopTunEgress` 先删 rule/表内 default 再 `nft delete table`。**配了代理则完全跳过**：不建表、不绑源地址、不装 SNAT。darwin 只有一张路由表，`next_hop` 在该平台不生效，实际网关跟随所绑网卡的系统路由；其他平台告警跳过
- **出站代理**（`egress.go`，仅 TUN 数据面使用）：`newEgress :48` 按 scheme 分派 `socks5`/`socks5h`/`http`/`https`/`trojan`；`probeEgress :122` 在 Init 探测（socks5 做完整方法协商+认证，http 只 TCP 建连，trojan 只 TLS 握手）；探测失败 → **回退直连**并打 **Warn** 日志（数据面仍可用，属降级）；不支持的 scheme 直接让启动失败。`describeEgress :131` 给日志提供不含凭据的出口描述（`socks5h://host:port` 等）。socks5 支持 RFC1928 CONNECT（`socks5ConnectRequest :307`）+ RFC1929 认证，`socks5h` 交给服务端解析域名；trojan 走 TLS + `sha256(password)[:56]` 头部（`trojanConnectRequest :475`）；UDP 方面 `egress_socks5_udp.go` 实现 RFC1928 §7 UDP ASSOCIATE（TCP 控制连接保活 + `RSV(2) FRAG(1) ATYP+ADDR+PORT PAYLOAD`，`FRAG!=0` 报错），`egress_trojan_udp.go` 实现 trojan 的 udp-associate 请求行（`hash CRLF 3 CRLF 0.0.0.0:0 CRLF`）与后续 `ATYP+ADDR+PORT LEN(2) PAYLOAD` 数据帧（数据帧不带 command 字节），地址编解码共用 `egress_proxy_addr.go`；`http`/`https` 天生只有 CONNECT，UDP 仍回落直连
- **包改写层（移植性最好的一层，供 NAT 风格转发/回退使用）**：`parseIPv4Packet :46` 解析 IPv4（拒绝分片/非 TCP/UDP，`checkIPv4Checksum`/`checkTransportChecksum` 校验）；`forwardPacket :226` 把客户端 → 假 IP 的包改成 `src=假IP、dst=真实IP、srcPort=新分配端口` 并重算校验和，`reversePacket :262` 把回包改回 `src=假IP、dst=客户端`；`domainForFakeIP :184` / `primaryRealIP :201` 走 DB 反查；`conntrack`（`flow.go:81`/`:124`）5 元组复用端口、TTL 2 分钟、容量 8192。TUN 数据面走用户态栈后不再需要 raw socket 注入，这一层保留为可移植实现（macOS 上可测）
- **注意**：所有 `nft`/`ip` 命令串行执行（`natMu`），建表失败会整体跳过、不留下半套 host route；`table_prefix` 只允许字母数字下划线；`next_hop` 必须是合法 IP（`:187`）；`proxy` 在 `use_tun: false` 时只会告警、不探测不建连
- **日志（分级口径）**：全程复用 `p.L()`（插件基类 `BP` 提供的 `*zap.Logger`），不引入新 logger，共 **250 个日志点**（Debug 137 / Info 50 / Warn 54 / Error 9）：
  - **Debug**（逐包、逐命令、逐连接，默认关闭）：`Init` 配置回显（`config resolved`，含 `proxy_configured` 布尔而非凭据）→ SQLite 打开/建表/探活 → 每查询（`query in`、AAAA 短路、响应复用、真实 IP 列表、假 IP 分配结果）→ nft 表复用/逐条 setup 命令/映射条数 → 每条 host route、每个候选 IP 的探测结果 → TUN 命令逐条执行、设备取名/复用/跳过、utun unit 与 wintun 适配器选择 → 每包入/出设备（`readFromTun :126` 用 `Check(zap.DebugLevel)` 保护，关闭时不解析报文）→ TCP/UDP 流建立与关闭（含 `bytes_up`/`bytes_down`/`duration`/`datagrams_*`）→ fake IP 反查与真实 IP 选择
  - **Info**（生命周期节点）：插件初始化完成（数据面/tun 设备/代理状态）、nft 表创建（`:152-183`）、映射更新（`:145`）、代理出口就绪、各平台 TUN 设备就绪、`tun data path started`/`tun device attached`/`detached`、transport forwarders 装载、插件关闭
  - **Warn**（可降级的异常）：`script` 字段废弃、代理配了但 `use_tun:false`、代理探测失败回退直连、单条 host route 失败、候选 IP 全不可达回退首个、真实 IP 写库失败、NAT 任务并发上限、单条 TCP/UDP 连接建立失败、设备写/关闭失败、平台不支持 TUN
  - **Error**（功能不可继续或数据不一致）：nft 表不可用导致映射跳过、写 nft 元素失败、SQLite 记录假 IP 失败、分配出的假 IP 非法、`use_tun` 起不来（插件无出口）
  - **无需日志的模块**：`packet.go`（纯解析/校验和，错误由调用方记录）、`tuncmd.go`/`tun.go`（纯命令计划与常量）、`tunio_bsd.go`（无插件上下文的设备读写，错误上抛给读写泵统一记录）
  - **开启方式**：mosdns 主配置 `log.level: debug`（Debug 只建议排障时开，逐包日志量很大）
- **依赖**：`github.com/metacubex/gvisor`（gVisor netstack 的维护分支，`go.mod` 要求 `go 1.20`，与全仓 `go 1.20` 一致）；`golang.zx2c4.com/wintun`（仅 Windows 目标编译）
- **平台支持**：darwin(amd64/arm64)、linux(amd64/arm/arm64/ppc64le)、freebsd(amd64)、windows(amd64)；`release.py` 里的 `linux/mipsle`、`linux/mips64le` 因上游 `modernc.org/libc` 不含 mips 支持而无法构建，与本插件无关
- **测试（171 项）**：`fakeip_nat_test.go`（分配 / 幂等 / 并发）、`nat_test.go`（参数解码、nft 输出解析、CIDR 聚合、快速路径、候选选择、tun 模式清掉非 tun 遗留的 nft 表、表形状校验与旧表重建）；`plugin_state_test.go`（状态记录往返、拒绝不安全目标、按记录删旧标记路径、有代理时删 SNAT 表、无状态时按 nft 表里的标记迁移清理、切回 nft 时删 tun 出口残留）、`route_mark_test.go`（15 项：安装命令序列（集合/两条链/两条 rule/default/ip rule）且二次 setup 不重复建对象 / 无 hop 回落系统默认网关 / 映射地址只进集合不写 host route / 集合写入失败回落 host route / 清理删 rule 与 default 并复位状态 / 打标模式跳过聚合循环 / 启动自检读回集合・两条链・ip rule・default（完整 / 缺失 / nft 报错三种情形） / `ip rule show` 的 hex・十进制・掩码・表名四种写法 / 只认 default 不认 host route / tun + fakeip 下打标停用 / tun + realip 把专用表 default 指向 tun 设备且不写 via / `hostRouteTable` 在打标模式下退到 main（专用表只留给带标记的包） / 集合写入失败回落时账本记 main）、`route_ledger_test.go`（6 项：写入即记账且只进内存 / flush 后落库 / forget 不落库而 flush 后删除 / 按账本清理 / 已知真实 IP 纳入 DB 行 / 只认账本行与其折叠聚合、运维路由判为 foreign）、`tun_test.go`（设备创建/复用/失败、`mth<N>` 取名、段首保留）、`egress_test.go`（链接解析、socks5 握手与认证、UDP 拒绝、trojan 头部、gost 协议探测与分表）、`packet_test.go`/`flow_test.go`（分包拒绝、校验和修复、端口映射、conntrack 过期、伪 IP 目标守卫）、`tunstack_test.go`（代理/直连目标选择、真实目的地址直接作为出口目标、入站归属过滤（假段/设备地址/已记录真实 IP 接受，陌生真实 IP 与非 IPv4 丢弃）、归属集合上限、UDP 端到端relay、TCP SYN→SYN-ACK）、`tunstack_icmp_test.go`（TTL 到期的 time exceeded、本机 UDP 探针的 port unreachable、本机 echo 直接进栈）、`tun_hop_display_test.go`（6 项：第 1 跳替身地址 / 无钩子回退段首 / `hopSource` 只虚拟化 time exceeded / `relayICMPError` 虚拟化 / port unreachable 保留真实源 / `hopOf` 回查段首）、`tun_echo_mode_test.go`（3 项：代理本地合成 echo 且保留 id/seq/payload、直连转发到真实 IP 且 pending 表保留客户端 id、未映射假 IP 静默）、`mapping_runtime_test.go`（重启恢复运行时表、nft 对账补写与 reserved、真实 IP 内存表随域删除）、`tun_egress_test.go`（路由表命令计划三种形态、`tun_route_table` 默认与非法名拒绝）、`tun_icmp_test.go`（12 项：`TestBuildClientUDPQuote` 引用构造 / `TestBuildICMPEchoIPv4` echo 字段与校验和 / `TestICMPErrorFromSocketError` errno→type・code / `TestICMPRelayTables` 流表与引用表 / `TestHandleICMPEchoAcceptsFakeIPOnly` 只吃发往 fake IP 的 echo / `TestBuildICMPErrorQuotesTransportHeader` 引用必须含 UDP 头 / `TestShouldProbeBounds` TTL 边界 / `TestProbeTableIsOneShot` 探测表一次性删除 / `TestProbeReplyRewritesHopAddress` 回包源地址落在段内且可反查 / `TestPtrAddrParsesReverseName` 反向名解析 / `TestHopFakeForSkipsAllocatedAddresses` 虚拟地址避开已用地址 / `TestHopNameSuffixDefaultAndValidation` 后缀默认跟随 table_prefix、下划线转换、非法值拒绝）

### 2.22 `ocserv_ctl`（定制）
- **文件**：`plugin/executable/ocserv_ctl/ocserv_ctl.go`（注册 `:37`）；`plugin/enabled_plugin.go:42` 导入
- **参数**：`socket` 与 `addr` 至多填一个 —— `socket` 是 occtl socket 文件（如 `/run/ocserv/occtl.socket`），`addr` 是 TCP 端点（`host:port`）；**两者都不填时插件保持禁用**：不调 occtl、不打标记，查询直接透传；`occtl_path`（默认 `occtl`）、`timeout`（单次调用上限，默认 3s）、`cache_ttl`（用户列表缓存，默认 15s）、`mark`（命中时给查询打的标记号，0 = 只记日志）
- **行为**：纯 DNS 链节点，不提供 CLI / HTTP。`Exec` 取 `qCtx.ReqMeta().ClientAddr` → 缓存未过期直接查表，否则执行 `occtl -s <socket|addr> -j show users` 并解析（键名归一化为 `username` / `remoteip` / `ipv4` / `id`）→ 源地址等于 `Remote IP`（客户端公网地址）或 `IPv4`（隧道内地址）即命中 → Debug 日志 `ocserv user identified` + 可选 `qCtx.AddMark(mark)`；未命中只记 Debug。任何 occtl 失败/超时只 Warn 并保留上一份快照，不阻塞 DNS
- **注意**：要放在 `sequence` 链首才有意义；JSON 字段以 ocserv 1.1.x 的 `"Username"` / `"Remote IP"` / `"IPv4"` / `"ID"` 为准，解析器同时接受空格、下划线、大小写变体
- **测试（9 项）**：`TestMarksQueryForRemoteIP`（源地址命中 + occtl argv 顺序）、`TestMarksQueryForVPNAddress`、`TestUnknownClientIsNotMarked`、`TestUserListIsCached`（缓存期内只调一次）、`TestOcctlFailureIsNotFatal`、`TestDisabledWithoutEndpoint`（未配置时不调用）、`TestMissingSocketFileSkipsCall`（socket 尚未创建时跳过）、`TestParseUsersNormalizesKeys`（键名与 CIDR/端口清洗）、`TestArgsDefaultsAndExclusivity`

### 2.23 `telegram_bot`（定制）
- **文件**：`plugin/executable/telegram_bot/telegram_bot.go`（主体与命令）、`telegram.go`（HTTP 客户端）、`config.go`（配置读写）、`permissions.go`（角色与权限）；`plugin/enabled_plugin.go` 导入（`_ telegram_bot` 在 `_ fakeip_nat` 之前）
- **依赖**：`github.com/go-telegram/bot v1.28.0`（长轮询 `Bot.Start`、`WithSkipGetMe` 避免启动期打 API、`WithServerURL` 便于镜像/测试）
- **参数**：`token`（BotFather 令牌，必填）、`chat_ids`（管理员 chat id 列表，使用 `default_role`）、`admins`（`chat_id` + `role` 精细绑定）、`roles`（命名权限集，`allow` 授权、`inherits` 继承其它角色，取并集）、`default_role`（默认 `admin`，内置角色拥有全部权限）；`fakeip_tags` / `ocserv_tags` / `radius_tags`（数组，可同时管多个插件实例，首项为默认目标）、`config_path`、`proxy`、`api_base`、`poll_timeout`(30s)。`chat_ids` 与 `admins` 合并，老配置只写 `chat_ids` 仍是全权管理员
- **权限**：`status`（`/status` `/plugins` `/plugin` `/perm`）、`fakeip`（`/fip` 及 `/list` `/stats` `/lookup` `/rev` `/del` `/clear`）、`ocserv`（`/vpn`）、`radius`（`/user`）、`config`（`/config` 读写）、`reload`（`/reload confirm`）、`exec_script`（`/exec`）、`admin`（全部）。未授权 chat 直接忽略，越权命令回 `permission denied: role "x" lacks "y"`
- **命令**：`/fip [tag] {tags|help|list [n]|get <domain|fake_ip>|add|del|stats|clear confirm}`、`/vpn [tag] {tags|help|users|status|sessions|kick|term|run <occtl args...>}`、`/user [tag] {tags|help|list|add <name> <pass> [group]|del|pass|enable|disable|group|sessions [active] [n]}`、`/exec <tag> <ip> <domain>`、`/perm`、`/status`、`/plugins`、`/plugin <tag>`、`/config {show|get|set|add|del|validate}`、`/reload confirm`
- **配置管理**：以 `yaml.Node` 树就地编辑，保留注释与顺序；`get/set` 支持 `plugins[1].tag` 这类下标路径；`add` 向 `log` 合并键或向 `data_providers` / `plugins` / `servers` 追加元素（拒绝重复 tag）；`del` 按 tag / 下标 / log 键删除；`validate` 在写前检查 tag/type、`servers[].exec` 与 `listeners`；每次写入先落 `<path>.bak.<unixts>` 备份，编码后再解析校验才 `rename`
- **/reload**：mosdns 无进程内重载（插件与监听在启动时一次性装配），因此校验配置后 `SendCloseSignal(errors.New(...))` 以非零码退出，交给 launchd / systemd / GoLand 拉起
- **注意**：`/exec` 只调用配置里已绑定的脚本（`script_path <ip> <domain>`），不接受任意命令；`exec_script` 为此新增 `AdminRun`
- **测试（25 项）**：命令解析与别名、fip 增删查改、occtl 透传、白名单、`httptest` 假服务端端到端（multipart 回复）、tag 数组合并、配置 `get/set/add/del/validate` 与备份、角色继承与权限门、继承环与未知权限拒绝

### 2.24 `radius`（定制）
- **文件**：`plugin/executable/radius/radius.go`（`Args` / `Admin` 接口 / 校验）、`radius_packet.go`（报文编解码、`User-Password` 链式异或、响应认证符、Message-Authenticator）、`radius_server.go`（UDP 收发与两个 handler）、`radius_store.go`（PBKDF2 + SQLite 两张表）；导入在 `plugin/enabled_plugin.go`（`_ query_summary` 之后）
- **参数**：`listen`（默认 `0.0.0.0:1812`）、`accounting_listen`（默认 `0.0.0.0:1813`，`off` / `0` 关闭）、`secret`（必填，与 ocserv 的 `radius secret` 一致）、`db_path`（默认 `radius.db`）
- **认证**：只支持 PAP（ocserv 的 `auth = radius` 走 `Access-Request` + `User-Password`）。报文头 length 与实际长度不符或属性长度越界即拒；`Access-Request` 带 `CHAP-Password` 而没有 `User-Password` 时明确回 Reject 并提示改用 PAP，不静默丢包。认证通过把 `group_name` 作为 `Class(25)` 回给 ocserv
- **记账**（RFC 2866）：`Start(1)` / `Start2(15)` 建会话并置 `active=1`，`Interim(3)` / `Alive(4)` 只更新用量，`Stop(2)` 写 `ended_at` 并置 `active=0`；请求认证符按 `MD5(code|id|len|16 个 0|attrs|secret)` 校验
- **存储**：`radius_users`（`name` 主键 + `password` + `group_name` + `enabled` + 时间戳）、`radius_sessions`（`session_id` 主键 + `name` + `remote_ip` + 起止时间 + 收发字节 + `active`），DSN 带 `busy_timeout(5000)` 与 WAL；密码是手写 PBKDF2-HMAC-SHA256（12000 轮、16 字节盐、32 字节 DK），不引入 `x/crypto`
- **管理入口**：`Admin` 接口 `Users` / `AddUser` / `DeleteUser` / `SetPassword` / `SetEnabled` / `Sessions`，另有 `SetGroup`，供 `telegram_bot` 的 `/user` 类型断言使用
- **注意**：`Exec` 是纯透传，插件不进 DNS 链，只借 `GetExecutables()` 被 bot 看见；账号表与 ocserv 的 `ocpasswd` 完全独立，ocserv 侧本地用户不再参与认证
- **测试（7 项）**：密码编解码往返、截断属性拒绝、哈希校验、Accept/Reject/未知用户/禁用账号端到端 UDP、客户端复算响应认证符、记账 Start/Stop 落库、`Admin` 校验与增删改查

### 2.25 `exec_script`（定制）
- **文件**：`plugin/executable/exec_script/exec_script.go`；注册 `:21`
- **参数**（`:24-28`）：`script_path`（必填）、`dedup_ttl`(300s)、`async`（默认 **true**，`:54-57`）
- **行为**（`:97-131`）：先跑 `next`，取响应里的每个 A/AAAA 的 IP，调 `script_path <ip> <qname>`；`async` 决定是否起 goroutine
- **去重**：同 IP 在 `dedup_ttl` 内只执行一次，并在每次执行时顺带清理过期项（`:68-84`）
- **注意**：脚本接收的是**真实 IP**；本插件不读写数据库，状态只在内存，进程重启即清空
- **管理入口**：`AdminRun(ctx, ip, domain)`（同步执行并返回合并输出），供 `telegram_bot` 的 `/exec` 使用；参数契约与 DNS 路径一致，无法注入任意命令

### 2.26 `query_matcher`
- **文件**：`plugin/matcher/query_matcher/query_matcher.go`；注册 `:39`
- **参数**（`:64-71`）：`client_ip[]`、`ecs[]`、`domain[]`、`qtype[]`、`qclass[]`
- **行为**：逐项构建 matcher 后逻辑与（`:88-129`）；**空组 = 不匹配**（`utils.go:119-121`）
- **预置**（`:41-59`）：`_qtype_A_AAAA`（qtype 1,28）、`_qtype_AAAA`（28）、`_query_edns0`（查询带 EDNS0，`:133-139`）

### 2.27 `response_matcher`
- **文件**：`plugin/matcher/response_matcher/response_matcher.go`；注册 `:38`
- **参数**（`:47-51`）：`rcode[]`、`ip[]`、`cname[]`
- **行为**：RCode 匹配、答案 IP 匹配、CNAME 匹配，三者逻辑与（`:68-99`）
- **预置** `_response_valid_answer`（`:40`）：答案里存在与问题完全对应（name/qtype/qclass 三元组相等）的记录（`:107-132`）——**只要求「有一个有效答案」，不看 rcode**

### 2.28 `misc_optm`（仅预置，无 type）
- **文件**：`plugin/executable/misc_optm/misc.go`；常量 `PluginType` 在 `:33` 但**没有** `RegNewPluginFunc`，只注册 `_misc_optm`（`:41`）
- **行为**（`:52-107`）：
  1. 非标准查询（非 QUERY、QR=1、多问题、非 IN）→ 直接 `REFUSED` 且**不走 `next`**（`:55-60`）
  2. 查询 EDNS0 UDP 大小压到 1200（`:63-67`，常量 `maxUDPSize` 在 `:37`）
  3. 响应后：A/AAAA 只留同类型答案并洗牌、改回问题名（`:78-92`）
  4. 响应里删 padding（`:95-97`）；查询没 EDNS0 就删响应 EDNS0（`:100-102`）

### 2.29 `query_summary`（仅预置）
- **文件**：`plugin/executable/query_summary/query_summary.go`；只注册 `_query_summary`（`:36`）
- **行为**（`:49-60+`）：先跑 `next`，再按「问题 + rcode + 耗时」打一行日志

### 2.30 `padding`（仅预置）
- **文件**：`plugin/executable/padding/padding.go`；三个预置（`:34-42`）
- **行为**：
  - `_pad_query`：查询补到 128 字节；回包时若原查询没有 EDNS0 就删响应 EDNS0、没有 padding 就删响应 padding（`:58-79`）
  - `_enable_conditional_response_padding`：仅在客户端先 pad 时才回 pad（`:89-105`）
  - `_enable_response_padding`：无条件按 468 字节回 pad（预置里 `Always: true`，`:40`；执行分支 `:95-97`）

---

## 3. 预置 tag 全表（21 个）

预置 tag = **不需要在 `plugins` 里定义**，直接在 `exec` / `if` 里写 tag 就能用。

| # | tag | 来源 | 等价于 |
|---|---|---|---|
| 1 | `_return` | `sequence.go:34` | 「到此结束」，不再执行后续节点 |
| 2 | `_drop_response` | `blackhole.go:38` | `blackhole{rcode: -1}`（不回包） |
| 3 | `_new_empty_response` | `blackhole.go:41` | `blackhole{rcode: 0}`（空答案 NOERROR） |
| 4 | `_new_servfail_response` | `blackhole.go:44` | `blackhole{rcode: 2}` |
| 5 | `_new_nxdomain_response` | `blackhole.go:47` | `blackhole{rcode: 3}` |
| 6 | `_prefer_ipv4` | `dual_selector.go:46` | `dual_selector{mode: 0}` |
| 7 | `_prefer_ipv6` | `dual_selector.go:49` | `dual_selector{mode: 1}` |
| 8 | `_misc_optm` | `misc.go:41` | `misc_optm`（无 type，必须用此 tag） |
| 9 | `_no_ecs` | `ecs.go:39` | 查询与响应都剥离 ECS |
| 10 | `_pad_query` | `padding.go:34` | 查询 pad 到 128 字节 |
| 11 | `_enable_conditional_response_padding` | `padding.go:37` | 条件性响应 padding |
| 12 | `_enable_response_padding` | `padding.go:40` | 无条件响应 padding（468 字节） |
| 13 | `_edns0_filter_no_edns0` | `filter.go:35` | `edns0_filter{no_edns: true}` |
| 14 | `_edns0_filter_ecs_only` | `filter.go:38` | `edns0_filter{accept: [8]}`（只留 ECS） |
| 15 | `_query_summary` | `query_summary.go:36` | `query_summary`（无 type） |
| 16 | `_default_cache` | `cache.go:49` | `cache{}`（内存、size=0 → 约 1024 条） |
| 17 | `_sleep_500ms` | `sleep.go:40` | `sleep{duration: 500}` |
| 18 | `_response_valid_answer` | `response_matcher.go:40` | 响应里存在与问题一一对应的答案 |
| 19 | `_qtype_A_AAAA` | `query_matcher.go:41` | `query_matcher{qtype: [1, 28]}` |
| 20 | `_qtype_AAAA` | `query_matcher.go:47` | `query_matcher{qtype: [28]}` |
| 21 | `_query_edns0` | `query_matcher.go:54` | 查询带有 EDNS0 |

> 预置 tag 与配置 tag 共用一个命名空间：你不能再定义 `tag: _return`（`register.go:139-149` 会 panic），但可以定义 `tag: my_cache` 再在 `exec` 里引用。
>
> 两个最容易被误解的语义：`_return` 是**真的终止**（不调 `next`，`sequence.go:79-81`）；`_drop_response` **不是丢包**，它把响应置空后继续走链，最终无人应答时由入口兜底成 SERVFAIL（`blackhole.go:157-158` + `entry_handler.go:118-122`）。

---

## 4. 新增插件：6 步

### 第 1 步：建目录

```
plugin/executable/<name>/<name>.go     # 改查询/改响应 → executable
plugin/matcher/<name>/<name>.go        # 只判断不修改 → matcher
```

### 第 2 步：定义 `PluginType` 与 `init()`

```go
const PluginType = "hello"

func init() {
    coremain.RegNewPluginFunc(PluginType, Init, func() interface{} { return new(Args) })
}
```

- type 名全局唯一，重复注册会 **panic**（`register.go:57-60`）。
- 想让用户「不用写 args」就能用，再加一个预置（见第 8 节）。

### 第 3 步：定义 `Args` 与 `Init`

```go
type Args struct {
    Threshold int    `yaml:"threshold"`
    Lists     []string `yaml:"lists"`
}

func Init(bp *coremain.BP, args interface{}) (coremain.Plugin, error) {
    a := args.(*Args)          // 框架已按 mapstructure 解好
    if a.Threshold <= 0 {
        return nil, fmt.Errorf("threshold must be > 0")
    }
    return &hello{BP: bp, args: a}, nil
}
```

- yaml key 用 `yaml:"..."` 标签；`Args` 里**未使用的字段不会报错**，但配置里写了 `Args` 没有的字段会因 `ErrorUnused=true` 直接启动失败（`run.go:139`）。

### 第 4 步：实现接口

**透传型（最常见）**

```go
type hello struct {
    *coremain.BP
    args *Args
}

var _ coremain.ExecutablePlugin = (*hello)(nil)

func (h *hello) Exec(ctx context.Context, qCtx *query_context.Context, next executable_seq.ExecutableChainNode) error {
    // 1) 读查询：qCtx.Q()、qCtx.ReqMeta()
    // 2) 读响应：qCtx.R()（可能为 nil，取决于你放在链的哪个位置）
    // 3) 改结果：qCtx.SetResponse(r) 并 return nil 表示终结
    // 4) 继续：把 next 交给框架
    return executable_seq.ExecChainNode(ctx, qCtx, next)
}
```

**终局型（命中即返回）**

```go
func (h *hello) Exec(ctx context.Context, qCtx *query_context.Context, next executable_seq.ExecutableChainNode) error {
    if r := h.buildResponse(qCtx.Q()); r != nil {
        qCtx.SetResponse(r)
        return nil            // 不调 next = 本条链结束
    }
    return executable_seq.ExecChainNode(ctx, qCtx, next)
}
```

**匹配器**

```go
type helloMatcher struct{ *coremain.BP }

var _ coremain.MatcherPlugin = (*helloMatcher)(nil)

func (m *helloMatcher) Match(_ context.Context, qCtx *query_context.Context) (bool, error) {
    if len(qCtx.Q().Question) != 1 {
        return false, nil     // 不要在这里假设响应存在
    }
    return qCtx.Q().Question[0].Qtype == dns.TypeA, nil
}
```

**资源清理**：持有 `sql.DB` / redis client / netlink / goroutine 的插件，要重写 `Close()`（内嵌 `BP.Close()` 是空实现，`register.go:206-208`）。

### 第 5 步：加进启用清单（最容易漏）

`plugin/enabled_plugin.go:23-51` 加一行空白导入：

```go
_ "github.com/ersonw/mosdns-v4/plugin/executable/hello"
```

漏了这一步 → `init()` 不执行 → 配置报 `plugin type hello not defined`（`register.go:90-93`）。

### 第 6 步：写配置并验证

```yaml
plugins:
  - tag: my_hello
    type: hello
    args:
      threshold: 3
      lists:
        - /etc/mosdns/list.txt

servers:
  - exec: main_seq
    listeners:
      - protocol: udp
        addr: 127.0.0.1:5353
```

```bash
go build ./...                  # 编译
go test ./plugin/...            # enabled_plugin_test 会跑一遍所有 init()
./mosdns start -c config.yaml   # 观察 "loading plugin" 日志
```

- 新插件默认**不会自动生效**：必须被某个 `sequence` 的 `exec` 引用，且该 sequence 是某个 `servers[].exec` 的入口。
- 想让插件带上 `/plugins/<tag>/` 的 HTTP 接口，再实现 `ServeHTTP`（`mosdns.go:156-158` 会自动挂）。

---

## 5. 扩展点速查（不止「加插件」）

| 想扩展 | 改哪里 | 关键约束 |
|---|---|---|
| 新增可执行步骤 | `plugin/executable/<name>` + `enabled_plugin.go` | 必须实现 `Executable` |
| 新增判断条件 | `plugin/matcher/<name>` + `enabled_plugin.go` | 必须实现 `Matcher`；`if:` 里只能写 matcher tag |
| 新增「零配置」开关 | `coremain.RegNewPersetPluginFunc` | tag 全局唯一，重复即 panic |
| 新增上游协议 | `pkg/upstream.NewUpstream`（`upstream.go:113`）+ `fast_forward` 参数 | `forward` 走的是另一套 `AddressToUpstream` |
| 新增缓存后端 | 实现 `pkg/cache.Backend`（`cache.go:33-46`）+ `cache.go:91-112` 分支 | 后端方法不能返回错误 |
| 新增数据源热重载 | `data_providers` + 实现 `data_provider.DataListener`（`data_provider.go:37-39`）| 更新失败只打日志（`:132-146`） |
| 新增 HTTP API | 插件实现 `ServeHTTP`，或用 `bp.M().GetHTTPAPIMux()` | 只能注册 `/plugins/<tag>/` 前缀（`mosdns.go:234-240` 注释） |
| 新增 CLI 子命令 | `coremain.AddSubCmd`（`run.go:89-91`），参考 `main.go:38-44` / `tools/init.go` | 子命令在 `init()` 里注册 |
| 新增指标 | `bp.GetMetricsReg()`（`register.go:202-204`）| 自动带 `plugin_<tag>_` 前缀 |
| 新增 server 协议 | `config.go:67` 注释 + `coremain/server.go:100-155` switch + `pkg/server` | `http` 目前是 Unix socket |
| 新增配置字段 | `coremain/config.go` 对应结构体 | 因 `ErrorUnused=true`，删改字段会破坏老配置 |

---

## 6. 插件开发反模式（都在这份代码里有迹可循）

1. **该调 `next` 却没调**：除了明确的「终局」语义，不调 `next` 等于把后面的链全部掐掉。参考 `_return`（`sequence.go:79-81`）是**故意**不调的。
2. **在 `Match` 里读 `qCtx.R()`**：`if` 可能出现在链的前段，此时 `R()` 是 nil。`response_matcher` 系列只应在「拿到响应之后」的链段使用。
3. **并发里直接改 `qCtx`**：`context.go:47` 明确非并发安全；`parallel`/`dual_selector` 都是先用 `Copy()`（`dual_selector.go:88`、`:124`）。
4. **在插件 `init()` 里做重活**：`enabled_plugin_test.go` 跑测试时会把所有 `init()` 执行一遍，任何 `panic`/阻塞都会让测试挂住。
5. **用 `panic` 报配置错误**：框架期望 `Init` 返回 `error`（`register.go:114`）；panic 会直接崩进程且没有「哪个插件、哪个字段」的上下文。
6. **阻塞主链**：`exec_script` 的默认异步（`async=true`）就是反例的正面写法；任何外部 IO 都应受 `ctx` 控制。
7. **忘记 `Close()`**：`sql.DB`（`fakeip_nat`）、redis client（`cache`、`reverse_lookup`）、netlink（`ipset_linux.go:76-78`）都需要释放。
8. **平台能力不写 build tag**：`ipset`/`nftset` 用 `//go:build linux` + `_other.go` 空实现（`ipset_other.go:39-41`），代价是**非 linux 上静默无效果**；新插件若依赖 linux，建议在 `Init` 里显式报错而不是静默降级。
9. **用 `fmt.Print` 打日志**：统一用 `bp.L()` / `bp.S()`，否则日志没有 tag、不受 level 控制、不进日志文件。
10. **依赖 `qCtx.Q()` 不被别人改**：`redirect` 会改 `Question[0].Name`（`redirect.go:101`）、`dual_selector` 会改 `Qtype`（`dual_selector.go:95`）；需要原始查询请用 `qCtx.OriginalQuery()`（`context.go:114`）。

---

## 7. 一页速查：从零加一个「按域名计数」的插件（示例路径）

| 步骤 | 具体动作 | 验证点 |
|---|---|---|
| 1 | 新建 `plugin/executable/domain_counter/domain_counter.go`，`PluginType = "domain_counter"` | `go build ./...` |
| 2 | `Args{ TopN int }`；`Init` 里校验并建 map | 启动不报错 |
| 3 | 实现 `Exec`：读 `qCtx.Q().Question[0].Name` 计数，再 `ExecChainNode(next)` | 计数在日志/指标可见 |
| 4 | `enabled_plugin.go` 加空白导入 | `mosdns start` 出现 `loading plugin ... type=domain_counter` |
| 5 | 配置里定义 `tag: dc`，并在某个 `sequence` 的 `exec` 里加 `- dc` | 该链路径上的查询被计数 |
| 6 | （可选）加 `GetMetricsReg().MustRegister(...)` 暴露到 `/metrics` | `curl /metrics` 看到 `mosdns_plugin_dc_*` |

> 关键顺序：**注册 → 导入 → 配置 → 被入口链引用**，四步缺一不会生效，且其中「导入」和「引用」两步失败时表现最不直观（一次是启动报 type 不存在，一次是完全静默）。
