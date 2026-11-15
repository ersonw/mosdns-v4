# 性能与内存治理

mosdns 在 VyOS 这类"内存小、CPU 还要分给转发面"的机器上长时间运行后，CPU 和 RSS
一起上涨，通常不是一次泄漏，而是几处"每次操作的代价随运行时间增长"叠加在一起。
这份文档记录 2026-11 这一轮改动的根因、改法和参数建议。

## 一、CPU：为什么"跑一段时间才涨"

| 位置 | 原实现 | 代价 | 现在 |
| --- | --- | --- | --- |
| `fakeip_nat/flow.go` conntrack | 每个转发包都 `sweepLocked` 全表扫描 | O(打开的连接数)/包；表接近 8192 后每包扫上万项 | 每 `1s` 最多扫一次，其余包 O(1) |
| `fakeip_nat/mapping_runtime.go` `putReal` | 每个 A/AAAA 应答都遍历整个 `byReal` | O(已记录 IP 总数)/应答，随域名数线性增长 | 只遍历本域名的上一份列表，O(8) |
| `fakeip_nat/nat.go` `syncNAT` | 每个新域名 `nft list map`（全量 dump + 正则） | O(已装映射数)/应答，还要起一个子进程 | 读内存镜像 `nftMirror`，只有启动和显式 dump 才读内核 |
| `fakeip_nat/nat.go` `ensureNFTTable` | 每个新域名 `nft list table` + 正则匹配 | 每次应答一个子进程 | 表验证一次后缓存；写元素失败才失效重验 |
| `fakeip_nat/nat.go` `aggregateManagedRoutes` | 每 30s 对每条路由重建一次 ledger collapse | O(路由²)，路由越多越烫 | `ownedPrefixSet()` 按 ledger 版本缓存，O(路由) |
| `fakeip_nat/fakeip_nat.go` `recordAndAllocate` | 每次应答 1 次 INSERT + 1 次 SELECT + 1 次真实 IP upsert | 单连接串行，缓存 TTL 到点就重来一遍 | 内存镜像命中即返回，不再查库 |
| `fakeip_nat/access_log.go` `recordAccess` | 每次应答一次 SQLite upsert | 每应答一次串行写盘 | 内存聚合，10s 或 2048 行批量落库 |

## 二、内存：为什么会涨、为什么不还

1. `runtimeMap` 里的 `byDomain / byFake / lastSeen / realByDomain / byReal` 随唯一域名增长，
   按 `record_ttl`（默认 7 天）才回收。这份数据是必要的，但回收扫描以前会把整张表读进
   一个 slice 再处理，峰值内存翻倍；现在流式扫描，只保留本次要处理的过期/刷新行。
2. Go 默认在 Linux 用 `MADV_FREE`，GC 释放的 span 仍然映射在进程里，所以 `top` 上的 RSS
   只涨不降。这是"看着像泄漏"的主因，靠 `debug.FreeOSMemory()` 才能真正还给内核。
3. SQLite 的 WAL 会一直长到 checkpoint 才截断，磁盘和 page cache 都会涨。建议在
   `fakeip.db` 所在目录定期 checkpoint，或把 `record_ttl` 调小。

## 三、新增的 `runtime:` 配置块

`coremain` 新增了可选字段，不写就完全保持原来的行为：

```yaml
runtime:
  maxprocs: 2               # GOMAXPROCS；0 = 保持探测到的核数
  gc_percent: 50            # GOGC；0 = 保持默认 100
  memory_limit: 256MiB      # 软内存上限（GOMEMLIMIT 语义）；留空 = 不设
  scavenge_interval: 10m    # 定期把空闲页还给内核；留空 = 不启用，最小 1m
```

生效点：`RunMosdns` 里在加载任何插件之前应用；`scavenge_interval` 到点后打印一次
`runtime memory`（heap/sys/goroutines）再 `FreeOSMemory()`，所以内存是缓慢爬升还是
锯齿状回收，日志里能直接看出来。

VyOS（2 核 / 1~2GB 内存的常见配置）建议：

```yaml
runtime:
  maxprocs: 2
  gc_percent: 50
  memory_limit: 384MiB
  scavenge_interval: 10m
```

`maxprocs` 别超过转发面实际能分到的核；DNS 是 IO 密集，核多反而增加 GC 和调度开销。

## 三之二、`self_guard`：把"卡到 SSH 进不去"挡在前面

`runtime` 那一组参数管的是"别无限长"，管不了"别把整机吃满"。一旦热路径占满所有核，
sshd 排在调度队列后面，运维连都连不进来——这和内存涨不涨是两件事。`self_guard` 专门补这一块：

```yaml
runtime:
  self_guard: true          # 总开关，默认 false
  guard_cpu_percent: 90     # 本进程占「整机」CPU 的比例（4 核 = 3.6 核）
  guard_mem_percent: 90     # RSS 占「系统总内存」的比例
  guard_interval: 5s        # 采样周期，最小 1s
  guard_sustain: 15s        # 条件要持续多久才动手
  guard_cooldown: 5m        # 降档持续的时长
```

采样：每 `guard_interval` 读一次 `/proc/self/stat`（utime+stime）与 `/proc/self/statm`（RSS）、
`/proc/meminfo`（MemTotal），算出两个比例。动作只有两类，**都不会让进程退出**：

| 触发 | 动作 | 日志 |
| --- | --- | --- |
| RSS ≥ `guard_mem_percent` 且持续 `guard_sustain` | `debug.FreeOSMemory()`（一次完整 GC + 把空闲页还给内核），30s 内不重复触发 | `self guard: memory pressure, returning pages` |
| CPU ≥ `guard_cpu_percent` 且持续 `guard_sustain` | `GOMAXPROCS` 降到 1，把核让给内核、sshd 和转发面 | `self guard: cpu saturation, downshifting gomaxprocs` |
| 降档到期但 CPU 仍 ≥ 阈值 | 冷却期顺延 `guard_cooldown`，不恢复 | `self guard: cpu still saturated, cooldown extended` |
| 降档到期且 CPU < 阈值的一半 | 恢复到配置的 `maxprocs` | `self guard: cpu recovered, gomaxprocs restored` |

关于"回收线程"，必须说明白：**Go 的 goroutine 是协作式的，没有任何外部手段可以 kill 或回收**。
`self_guard` 能做的是：把不该继续占的页还给内核、把并行度降下来、以及在 goroutine 数超过
启动基线的 4 倍（且不低于 512）时打 `self guard: goroutine growth` 告警，把泄漏暴露在日志里，
而不是等它把机器拖死。真要清理泄露的 goroutine，只能靠修代码或重启进程。

同一套参数在 VyOS 上的完整建议：

```yaml
runtime:
  maxprocs: 2
  gc_percent: 50
  memory_limit: 384MiB
  scavenge_interval: 10m
  self_guard: true
  guard_cpu_percent: 90
  guard_mem_percent: 90
```

`self_guard` 只在 Linux 上生效（依赖 `/proc`）；其他平台启动时会打一条
`self guard disabled: process accounting requires linux /proc`，不影响服务。

## 四、fakeip_nat 参数建议

| 参数 | 建议 | 说明 |
| --- | --- | --- |
| `record_ttl` | `168h` 起步，域名量大的机器可降到 `72h` | 决定 `runtimeMap` 和 nft map 的上限 |
| `access_log` | 不需要访问审计就关掉 | 关了就没有 `access` 表增长和落库 |
| `access_ttl` | 打开时设 `168h` 以内 | 超过一周的访问行没有价值 |
| `route_aggregation_interval` | 保持默认 30s | 聚合本身已改成 O(路由)；间隔再短只是多扫几次 |
| `nat_sync_wait` | 不要设成 0 | 0 会让应答不等 DNAT 就下发 |
| `use_tun` | 二选一，别和 nft 模式混用 | 混用时 `cleanupDataPath` 仍会尝试删表 |

`range_size` / `ipv4_range` 不要开得过小又频繁改：fake ip 复用会擦掉仍然有效的映射。

## 五、上线后怎么验证

1. `/debug/pprof/` 已挂在 API HTTP 上（`api.http` 配了才会监听）：
   - CPU：`go tool pprof http://<addr>/debug/pprof/profile?seconds=30`
   - 分配：`go tool pprof http://<addr>/debug/pprof/allocs`
   - goroutine：`curl http://<addr>/debug/pprof/goroutine?debug=2`
2. `/metrics` 里有 Go collector：关注 `go_memstats_heap_inuse_bytes`、
   `go_goroutines`、`go_gc_duration_seconds`。
3. 空白对照：改之前的二进制，跑一天看 `nft list map | wc -l` 的增长曲线；
   改之后同样的流量，`nft` 元素数量应该只随唯一域名增长，而 CPU 不再跟着它线性涨。
4. 自己压测：`dig +short @<addr> -p 53 <随机域名>` 循环，观察 `top -H` 的 GC 线程占比。
