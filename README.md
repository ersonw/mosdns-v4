# ADD  
```shell
git tag v4.0.0 && git push origin v4.0.0     # 触发 release
gh workflow run release.yml -f version=v4.0.0 # 或手动


sudo install -m 755 etc/ocserv/ocserv-updown.sh /usr/libexec/vyos/op_mode/ocserv-updown-script.sh
sudo install -m 755 etc/ocserv/ocserv_notify.py /usr/libexec/vyos/op_mode/ocserv_notify.py
sudo systemctl restart ocserv

```
### exec_script
```yaml
  - tag: call_route_script
    type: exec_script
    args:
      script_path: /scripts/add_ocserv_route.sh
      dedup_ttl: 300
```
### fakeip_nat
默认数据面是内置 NAT：插件自己创建 `fakeip_<table_prefix>` nftables 表（dnat_map +
prerouting/forward/postrouting），探测候选真实 IP 的可达性，写 `/32` host route 并做严格 CIDR 聚合。
`script` 回调已移除（旧配置里的 `script` 字段会被忽略并打一条告警）。
```yaml
  - tag: fakeip_oversea
    type: fakeip_nat
    args:
      table_prefix: "oversea"
      ipv4_range: "198.18.0.0/16"
      hop_name_suffix: "oversea"        # traceroute 主机名后缀，留空复用 table_prefix
      next_hop: "10.131.160.3"
      next_hop_dev: "eth0"
      route_table: "main"       # 默认 main；自定义表名仅 Linux 支持，macOS/Windows 回退 main
      route_aggregation: true   # 默认 true：每 30 秒扫描路由表，把指向出口的 /32 聚合为 CIDR
      route_mark: 0             # 默认 0 关闭；非 0 表示按目的地址打标分流（见下文；tun 下 realip 与 fakeip 都可用）
      route_rule_priority: 1000 # 打标模式下那条 ip rule 的优先级，与既有策略规则冲突时调大
      realip: false             # 默认 false（发 fake IP）；true 则不分配假 IP、不做 DNAT，只按真实 IP 分流（配 route_mark 时打标，tun 下进设备）
      mss_clamp: 0              # 默认 0 关闭；出口隧道 MTU 1400 时填 1360，改写 SYN/SYN-ACK 的 MSS
```

打开 `use_tun` 后改走 TUN 数据面：插件向系统申请 tun 网卡，把网卡地址设为 `ipv4_range` 的段首地址
并带上**与网段相同的掩码**（例如 `198.18.0.1/15`），内核据此自动生成整段的 connected 路由
（`198.18.0.0/15 dev mth0 proto kernel scope link src 198.18.0.1`），出站选源与回程下一跳都由
这条路由提供；只有网段是 `/32` 时才需要显式补一条 `ip route replace`。Linux 上还会 best effort
关掉该设备的 IPv6（`net.ipv6.conf.<dev>.disable_ipv6=1`），避免内核把 MLD/DAD 报文写进只处理
IPv4 的栈。段首地址由配置的网段推导、被保留，不会再分配给任何域名。设备命名按平台不同：Linux 从 `mth0` 起取第一个空闲编号；macOS 的 utun
编号由内核分配（`tun_dev` 留空即可，指定一个已存在的 `utunN` 会被拒绝，因为那是别的进程的设备）；
FreeBSD 取空闲的 `/dev/tun<N>`；Windows 用 Wintun。utun/tun 都是点对点接口，`ifconfig` 必须同时
给出对端地址，插件把对端也填成段首地址（`inet <段首> <段首> netmask 255.255.255.255`），
再由整段路由把流量收进设备。创建网卡在所有平台都需要 root / 管理员权限。
`proxy` 传入 socks5 / http / trojan 链接时作为该数据面的出站代理；探测不通过会回退直连并报错日志。
TCP 走 CONNECT；UDP 上 socks5 用 RFC 1928 UDP ASSOCIATE、trojan 用流内 udp-associate 请求行 +
长度前缀数据帧，两者都能承载 UDP，只有 `http`/`https` 因为协议本身只有 CONNECT 而回落直连。
`socks5://` 默认在本地解析目标，但本机解析器往往就是本插件自己，答复会是本段的伪 IP；插件会识别这种
答复并保留域名交给代理去解析（等价于 `socks5h://`），所以配置成 `socks5://` 也不会把 `198.18.x.x`
发给代理。其余出口（`http`/`https`/`trojan`）始终原样传域名。

`gost://user:pass@host:1080` 对应 gost 不带协议启动的监听（`gost -L=user:pass@:1080`，协议由服务端
按首字节嗅探）。插件会为该地址同时构造 socks5h、socks5、trojan、https、http 五种出口，启动时各探测
一次并计时：能握手的保留，握不上的剔除，日志 `gost outlet protocols selected` 列出 `tcp_protocols`
（按握手耗时从快到慢）与 `udp_protocols`（只含真正接受了 UDP ASSOCIATE 的协议，同样按耗时排序）。
之后按流量类型各走各的：TCP 只用 `tcp_protocols` 里最快的那个，连不上就退到下一个；UDP 只用
`udp_protocols`，为空则直接走宿主机网络（http/https 只有 CONNECT，本来就不承载 UDP）。某个协议这次
连不上就换下一个，整张列表都失败则直接走宿主机网络（等同没配代理）。若五种全部探测失败，启动日志
仍然是 `proxy is not usable, falling back to direct egress`。
ICMP echo 不经过任何代理协议（socks5 / trojan / http 都不承载 ICMP）。配了代理时，发往假 IP 的
echo 请求**由插件本地合成 echo reply**（保留客户端的 id、序列号和 payload），因为转发出去只可能超时：
这一跳的 `ping` 反映的是本设备而不是真实主机。没有代理时，echo 走宿主机的原始套接字，并把该
socket 与每次逐跳探测的 UDP socket 一起绑定到 `next_hop_dev`（Linux `SO_BINDTODEVICE`、
macOS `IP_BOUND_IF`），因此 `ping` 和 `traceroute` 都走 `next_hop`/`next_hop_dev` 指定的路径而不是
系统默认路由；平台没有这种绑定能力时（例如 FreeBSD/Windows）保持 socket 不绑定，启动日志
`tun icmp: icmp socket stays on the system route` 说明这一点，不会静默忽略配置。

TUN 数据面没有代理时，出口 socket 需要自己选路并改写源地址。Linux 上插件新建一张专用路由表
（`tun_route_table`，默认 `100`），写入 `default via <next_hop> dev <next_hop_dev>`，再加一条
`ip rule from <ipv4_range> to !<ipv4_range> lookup <table>`：只有**目标在段外**的包才进这张表，
客户端发往 fake IP 的包（源地址同样是段首）不会被拽出去、仍按主表的 connected 路由进 tun。
源地址用段内地址（段首 `.1`，设备已持有该地址），网卡绑定同时生效（Linux `SO_BINDTODEVICE`、
macOS `IP_BOUND_IF`）。

出站前还要做 **SNAT**：Linux 在独立 nft 表 `<prefix>_tun_snat` 里装
`oifname <next_hop_dev> ip saddr <ipv4_range> masquerade`，把段首源地址改写成宿主地址，否则
包会带着 `198.18.x.x` 源地址离开物理网卡、上游网关无法回程。选路发生在改写之前，所以
`next_hop` 决定的路由不会被 SNAT 干扰；这张表和 NAT 数据面的 DNAT 表互不删除。macOS 的出口
socket 本来就用宿主地址（无法把段首绑到别的接口），等价于改写后的状态，只打一条 Info 日志，
不动 `pf`。

`next_hop` 留空时回落系统默认路由的网关/网卡；两者都留空则完全不建表、不绑源地址、不装 SNAT，
保持原来的直连行为。配了代理时上述表与 SNAT 都不会创建，出口就是代理链路
（`console` 里可见 `tun egress: proxy carries the outlet`）。macOS 只有一张路由表、没有
`ip rule`，所以只做源地址 + `next_hop_dev` 网卡绑定，`next_hop` 在该平台不生效，
**指定网关这一步仅在 Linux 生效**。
ICMP 也按地址翻译（SNAT）语义处理：`ping` 发往 fake IP 的 echo 请求被转发到真实 IP，
回包把源地址改写回 fake IP；UDP 出口收到的 port unreachable / time exceeded 同样改写后
回给客户端，引用的报文是客户端实际发出的那份（含 IP 头与 UDP 头，短于 IP 头 + 8 字节
传输头的引用会被客户端内核按 bad length 丢弃），源地址保留真实来源。
客户端 TTL 2..30 的 UDP 探针（`traceroute`）不由本设备代答：插件用同样的 TTL 向真实 IP
再探一次，把应答那一跳的真实地址分配为段内一个虚拟地址（段内、避开已分配的
fake IP；起点由真实地址的哈希决定，所以同一跳每轮拿到同一地址，冲突时向低位顺延），用这个虚拟地址做回包源地址、客户端原报文做引用回给客户端，所以回包一定落在
客户端发往 tun 的路由范围内。该虚拟地址的反向解析（PTR）返回真实跳地址，`traceroute`
因此显示 `192.168.10.1.mosdns (198.19.x.y)`（后缀由 `hop_name_suffix` 指定，不写则复用
`table_prefix`（下划线转连字符）；单独的点分四段不是合法主机名，解析器会丢弃）；前提是客户端把 DNS 指向本插件，
否则 PTR 走上游、客户端只能看到地址。
macOS 客户端不想改全局 DNS 时，只让反向解析走插件即可：

```sh
sudo mkdir -p /etc/resolver
printf 'nameserver 127.0.0.1\nport 53\n' | sudo tee /etc/resolver/in-addr.arpa
sudo killall -HUP mDNSResponder
```

删掉 `/etc/resolver/in-addr.arpa` 即恢复。每个探针一张一次性表项（探测 socket
本地端口 → 客户端 / fake IP / 引用报文），应答到达即删除，1.2s 超时也删除；hop 的虚拟
地址表项在该地址的反向解析被回答后立即删除（5s 过期与 5s 周期清理兜底），不会跨探测累积。出口 socket 报错时即使 raw socket 不可用也会补一条
同样的回复，不会让客户端超时。

TUN 数据面由进程内的用户态 TCP/IP 栈（gVisor netstack）终止连接，再按目标拨号。
设备按平台实现：Linux 用 `/dev/net/tun`，macOS 用 utun，FreeBSD 用 `/dev/tun`，
Windows 用 Wintun（需要随程序附带 `wintun.dll` 并以管理员身份运行）：
有可用代理时把 **域名** 直接交给代理（`CONNECT domain:port`），没有代理时回查数据库里该域名的
**最近真实 IP** 后再直连。因此 `use_tun: true` 需要 Go 1.20 及以上构建（`go.mod` 已标注 `go 1.20`），
并依赖 `github.com/metacubex/gvisor`。
```yaml
  - tag: fakeip_tun
    type: fakeip_nat
    args:
      table_prefix: "tun"
      ipv4_range: "198.19.0.0/16"
      use_tun: true
      tun_dev: ""                        # 留空自动申请 mth0/mth1…；填名字则复用同名设备
      tun_mtu: 0                         # 0 = 自动：直连 1500，代理出口 1400；显式值优先
      proxy: "socks5h://user:pass@10.0.0.9:1080"   # 或 http://、https://、trojan://pass@host:443?sni=host、gost://user:pass@host:1080
      proxy_insecure: false              # 仅自签证书的 https / trojan 需要打开
      # 无代理时的直连出口：默认路由 = 下一跳 + 下一跳网卡，源地址 = 段内地址
      next_hop: "192.168.1.1"            # 留空则用系统默认路由的网关
      next_hop_dev: "en0"                # 留空则由路由查找决定；填了则同时绑定该网卡
      tun_route_table: 100               # 专用路由表号，仅 Linux 建表
      record_ttl: "168h"                 # 记录保留期；留空 = 7 天，"0" = 不清理
      access_log: true                    # 记录每个源 IP 解析了哪些域名，默认 true
      access_ttl: "168h"                  # 访问记录保留期；留空 = 7 天，"0" = 不清理
```

`access_log` 打开后，每回答一个 fake IP 就在同一份 SQLite 的 `<table_prefix>_access` 表里记一行
`(client_ip, domain)`，带 `fake_ip`、`first_seen`、`last_seen`、`hits`；真实 IP 不重复存，读取时
从 real IP 表按域名取最新一条，所以之后学到的地址也能看到。写入在应答路径上但失败只告警，
不影响查询；`access_ttl` 与映射共用同一个清理循环（间隔取两者较小的 TTL）。这些记录由
telegram_bot 的 `/access` 导出成 Excel。

`record_ttl` 控制数据库与内存里映射记录的保留期：启动 5 秒后先扫一次，之后每
`min(record_ttl, 1h)`（不低于 1 分钟）扫一次，把「内存 touch / 库内 `last_seen` / `created_at`
三者最大值」都早于 cutoff 的域名及其 `real_ips` 删掉，`pending` 行不受影响。清理在单个事务里
完成，提交成功后才把地址放回可用池，所以被回收的低位 fake IP 会被下一个域名重新拿到。
老库第一次运行不会被整表误删。

TUN 下的假 IP 分配从段内第 2 个地址开始（段首 `.1` 归网卡所有）。升级到该模式前，
请确认 `<prefix>_mapping` 里没有域名正好占着段首地址。

#### 目的地址打标路由（非 TUN，`route_mark`）

非 tun 数据面本来给每条解析出的真实 IP 写一条 `/32` host route，默认落进主表 `main`。网关解析量一大，
主表就堆满运维自己也认不出的条目，重启和重载都不保证清干净。把 `route_mark` 填成非 0 后，这套状态
完全移出路由表：

1. 真实 IP 只进 nft 集合 `real_ipv4`（`type ipv4_addr; flags timeout; timeout 1h`），不再写任何 host route；
   过期地址没人续期就自己消失，不需要额外的清扫循环。
2. 在 `fakeip_<prefix>` 里新增两条链：`mark_prerouting`（prerouting，priority 0，排在 DNAT 的 -100 之后，
   所以 fake-ip 模式下此时目的地址已经是真实 IP）与 `mark_output`（`type route hook output`，本机产生的
   流量改 mark 后会重新寻路），各自把「目的地址命中集合」的包 `meta mark set <route_mark>`。
3. `ip route replace default [via <next_hop>] [dev <next_hop_dev>] table <route_table>` 建出专用表里唯一的
   default（`next_hop` / `next_hop_dev` 留空时取系统默认网关），再
   `ip rule add fwmark <route_mark> lookup <route_table> prio <route_rule_priority>`。只有带标记的包查这张表。

```yaml
      route_table: "oversea"    # 必须显式命名专用表，填 main 会被拒绝
      route_mark: 256           # 0=关闭；取值避开 gost -M / wg 已用的 fwmark 位
      route_rule_priority: 1000 # 1..32766，与既有策略规则冲突时调大
```

边界：

- 非映射流量不查专用表，`ip rule` 只匹配带标记的包，主表不再被污染；
- 打标模式下 `route_aggregation` 的扫描直接跳过：地址不在任何路由表里，无可折叠也无可清理；
- 集合写入失败会回落成写 host route 并打 Warn，数据面不断流；此时路由写进 **main**（专用表只留给带标记的包，
  把回落路由写进去等于白写），账本同样记 `main`，停机时按记录原样删除；nft 对象或 `ip rule` 装不上时整体回落，
  `route_mark` 只打 Error，不影响 DNS 服务；
- 仅 Linux 支持，其他平台启动即报错；
- 两种数据面都可用，但语义不同：
  - 非 tun：打标替代「每个真实 IP 写一条 /32」，命中目标的包查专用表，主表不被灌满；
  - tun + `realip`：DNS 答案保持真实 IP，打标把它们**路由进 tun 网卡**（专用表 default 为 `dev <tun_dev>`），
    再交给出口——配了 `proxy` 就走代理，没配就按 `next_hop`/`next_hop_dev`（未填则取系统默认路由）
    钉住的出口路由直连；
  - tun + `fakeip`：假 IP 整段由设备路由接进设备，值得打标的只有应答里的**真实 IP**——它们由栈自己拨号出去。
    无代理时插件把每条应答的真实 IP 写进 nft 集合，打标后的包按专用表 default 走 `next_hop`/`next_hop_dev`
    （专用表 **不回指设备**，否则栈自己的拨号又被送回设备形成回环）；代理生效时打标整体不装，
    因为出口由代理拨号，标记只会和它抢路；
- NAT 数据面的 postrouting 只做 `ct status dnat masquerade`：被本插件 DNAT 的连接才改写源地址，
  不再按出口网卡匹配，避免把同一网卡上的其它流量（含宿主自身）一起 SNAT；
- 假段本身有一条独立的例外规则：`ip rule add to <ipv4_range> lookup main prio 5`
  紧随其后 `ip rule del` 同规格（幂等）。原因是网关常常有自己的策略路由——VyOS 会把所有
  非 CN 目的地打上 `fwmark 0xa`，在 `prio 10` 查海外表，假 IP（198.18/15 永远不在 CN 集合里）
  就在查到 `main` 之前被抢走、直接从隧道出去，设备一个包都收不到。这条规则不受 mark 影响，
  目的地址落在假段就只查 `main`，也就是设备那条 kernel 路由；它装在出口分支之前，
  所以代理生效时也照样装（代理只影响栈自己拨号的出口）。停机时按同一规格删除。
  范围和优先级（以及出口的 `tun_route_table` + 范围）都会写进 `plugin_state`
  的 `fake_range_rule` / `tun_egress` 两条记录：启动时按记录删掉与当前配置不一致的旧对象
  （改了 `ipv4_range` 或 `tun_route_table` 也能找到），切回非 tun 时由启动清理按记录删除，
  正常停机删完即清记录；被 `kill -9` 打断则留记录给下一轮，规则本身也会先 `del` 再 `add`。
- 退出路径：所有清理都挂在插件的 `Close` 上，能不能清干净取决于是否走到它。这条链分三层：
  `coremain` 在 `RunMosdns` 里登记运行中的实例并暴露 `RequestShutdown` / `WaitShutdown`；
  service 模式下 kardianos 的 stop 回调（`serverService.Stop`）驱动关闭并等它结束（限时 20s），
  非 service 模式由 `watchShutdownSignals` 监听 SIGTERM/SIGINT 做同样的事，重复信号立即强退；
  `kill -9`、OOM 这类拿不到回调的场景由下一轮启动按 `plugin_state` 记录清理。主动关闭以
  `ErrShutdownRequested` 标记，进程退出码 0，不会被 systemd 计成失败；
- tun 直连出口的 `ip rule from <range> to !<range> lookup <table>` 在启用打标时带
  `prio <route_rule_priority-1>`，保证它先于 `fwmark` 规则命中，插件自己的 socket 不会被自己的标记送回设备；
- `realip` 且未设 `route_mark` 时启动会打 Warn：每个应答都会往 `route_table`（默认 main）写一条 host route，
  整机选路都会受影响，打标才是推荐形态；
- 打标规则带源地址条件 `ip saddr != <ipv4_range>`：插件自己拨号的 socket 源地址落在该网段，
  若被标记就会把承载流量的 socket 又送进设备，形成回环；
- tun + realip 时 netstack 接受非假 IP 的目的地址：这类包是被标记路由进来的，直接以该地址为出口目标，
  不再反查 fake IP 映射；
- 清理只做三件事：删 `ip rule`、删专用表的 default、删整张 nft 表，不会残留；
- `nft delete table` 不再看 `use_tun`：tun 模式自己建不了这张表，存在的只可能是上次非 tun 运行留下的，
  启动前（`cleanupStaleNFTTable`）与退出时都会删掉。否则它挂在 prerouting 上的 DNAT 会先改写目的地址，
  包按改写后的真实 IP 从主表走掉，tun 设备根本收不到；
- 组合本身**不做启动校验**：`use_tun` + `fakeip` + `route_mark` 是合法配置，是否真正打标在运行时由
  `markRoutingEnabled` 决定（`tun` + `fakeip` + 代理生效 → 不装；其余 → 装）。以前这条组合会返回错误，
  结果是整个 mosdns 起不来，所以校验只保留「值本身没法用」的三条（`route_rule_priority` 范围、
  平台是否支持命名路由表、`route_table` 不能是 `main`）；
- 装上后立刻自检并写日志：`route mark: startup check passed`（带 `set` / `set_size` /
  `mark_chains` / `ip_rule` / `default_route` 五个字段）；任一对象缺失则打 Warn
  `route mark: startup check found the mark path incomplete`，不会等到主表被灌满才发现。

- 设备只收自己的包：`readFromTun` 进栈前先过 `ownsTunDestination`——目的地址必须落在
  `ipv4_range`、设备自身地址，或本次运行真正路由进设备（打标成功 / 启动时恢复）的真实 IP 集合里，
  其它 IPv4 包直接丢弃（`fakeip nat: packet for an unowned destination dropped`）。被别的路由
  塞进设备的流量不会被插件代拨出去；该集合上限 4096 条，超限按最旧淘汰；
- 上一轮装过的系统对象由记录驱动清理，不靠猜：`<table_prefix>_plugin_state` 存下实际的
  `route_mark` / `route_table`，启动时若与当前配置不一致、或 `route_mark` 已被删除，就按记录
  精确删掉 `ip rule fwmark <旧标记> lookup <旧表>` 与那张表的 default 路由（日志
  `route mark: removed the policy rule a previous run installed`）；有代理时启动先删掉
  `<table_prefix>_tun_snat` 这张只属于直连出口的表（日志
  `tun egress: removed the snat table a proxied run does not use`），避免模式切换后残留；
- 更早的构建没有状态表，它留下的 `ip rule fwmark ...` 仍可从自己的 nft 表里把标记读出来，
  启动时据此精确删除（日志 `route mark: removing the mark path a previous build left behind`）；
  从 tun 切回 nft 时则删掉 tun 出口的 SNAT 表与 `from <range>` 的规则（不改那张表的 default
  路由，因为它可能是机器自己在用的表）；
- tun 数据面能承载 DNS：`readFromTun` 对目的端口 53 的包（UDP/TCP）放行，`relayUDP`/`relayTCP`
  把 DNS 一律转到本机解析器 `127.0.0.1:53`（也就是 mosdns 自己），所以客户端把 DNS 指到
  tun 网关地址、或指到公网解析器但被路由进 tun，都能拿到应答（`tun dns: query relayed to the
  host resolver`）；设备地址上非 53 的 UDP 仍按原样回 ICMP port unreachable；
- 启动队列：Init 只做“数据面必须先有”的事（打开库、建表、装当前形状的对象、起设备），
  遗留清理（残留 host route 扫描、非 tun 启动时的 tun 出口清理）进 `startup_queue.go` 的队列，
  Init 返回后由单个协程按顺序执行并逐项打日志（`fakeip nat: slow startup step`，超过 1 秒才 Info）。
  mosdns 在所有插件 Init 返回前不提供解析，这类清理每个对象一次 exec，攒下来就是几十秒
  `ping: Unknown host`；`Close` 会先 `startupWG.Wait()` 等队列排空，再删本轮自己的路由；
- Init 收尾日志带 `init_elapsed`，另有 `proxy-probe` / `legacy-mark-sweep` / `tun-data-path`
  三个分步耗时，可直接指出是代理探测、迁移清理还是设备启动慢；
- 自动 tun 设备名（未配置 `tun_dev`）改成两条全量列举：`ip -o link show` 取已占用的
  `mth<N>`，`ip -o addr show` 找带保留地址的设备复用，再取最低空闲索引；旧实现逐个探测
  `mth0..mth63`（最多一二百次 exec），在没有 `tun_dev` 的机器上会拖慢启动；
- 清理前先判存在性：`nft list table` 不存在就只记 Debug，存在但 `delete` 失败则 Warn
  （`fakeip nat: removing the stale nft table failed` / `tun egress: removing the snat table failed`）；
  `nft` 本身不在 PATH 时单独 Warn，避免把"删不掉"伪装成"本来就没有"；
- 启动时校验已有 nft 表：`ensureNFTTable` 读回 `nft list table`，若 postrouting 仍是旧版的
  `oifname <dev> masquerade`、或缺少当前的 DNAT/drop/mss 规则，就删表重建（日志
  `fakeip nat: rebuilding the nft table so its rules match the configuration`），
  避免升级二进制后继续沿用旧表的宽匹配；
- 清理扫描只删自己的路由：`cleanupDataPath` / `sweepResidualRoutes` / `pruneManagedRoutes`
  扫到前缀后先过 `foreignRoute`——账本里没有逐条记录、也不是账本行折叠出的聚合块时跳过，
  运维自己写的同网关路由不会被误删（账本为空的旧场景仍按扫描兜底）。

#### TUN 下的 TCP / UDP / ICMP 语义

TCP、UDP、ICMP echo 三者都按 **SNAT（地址翻译）** 处理，而不是各自独立的替身：
客户端发往假 IP 的包被换成真实 IP 送出去，回包的源地址改回假 IP（或该跳的虚拟地址）再注入 tun。

**主机语义（段首地址）**：段首地址以 `/32` 注册为栈的本地地址，`ping <段首>` 由用户态栈直接
回 echo reply；发往段首的 UDP 探针回 ICMP port unreachable，所以 `traceroute <段首>`
第 1 跳就显示到达。TTL 为 1 且目的不是段首的包由插件构造 ICMP time exceeded。
目的既不是段首、又从 `<prefix>_mapping` 查不到真实 IP 的包不回（客户端超时）。

**第 1 跳为什么不能直接用段首地址**：回包的源地址若是段首（也就是客户端自己的本地地址，
`198.18.0.1`），Linux 的输入路由会按 martian source 直接丢弃，`traceroute` 只能显示 `*`。
所以这一跳和后面的跳一样走虚拟化：源地址取段内一个替身地址，它的 PTR 记录返回
`<段首地址>.<hop_name_suffix>`，于是第 1 跳显示成 `198.18.0.1.mosdns (198.19.240.7)`。
本机探测和下游探测因此看到同一种形式。

**UDP**：`relayUDP` 用用户态栈终止一个 UDP 流后按目标拨号，回包再改写回客户端。流表按
5 元组复用（TTL 2 分钟、上限 8192）。出口 socket 报错时按 errno 生成 ICMP 错误回给客户端：
`ECONNREFUSED → type 3 code 3`、`EHOSTUNREACH → 3/1`、`ENETUNREACH → 3/0`；即使 raw socket
不可用也会注入这一条，客户端不会一直等到超时。

**ICMP echo**：发往假 IP 的 echo request 由 `handleICMPEcho` 拦下（不进栈）。配了代理时**本地
合成 echo reply**（见上文）：代理协议不承载 ICMP，转发出去只会超时。没有代理时才用 raw ICMP
socket 以真实 IP 为源重新发出去（socket 绑定 `next_hop_dev`），标识/序列号改写并登记在 `echoes`
表（10s 过期）；回包（echo reply）按表项改回假 IP 后注入 tun，所以 `ping <假 IP>` 得到的是真实
主机的回包。未分配映射的假 IP 在任何模式下都不回。

**ICMP 错误**：真实路由器返回的 port unreachable / time exceeded 由 raw socket 读回，按其
引用的传输头定位客户端流。**time exceeded 来自路上的路由器，按跳虚拟化**（源地址换成段内
替身地址，PTR 返回真实路由器地址 + 后缀），和 `probeReply` 走同一条虚拟化逻辑；port/host
unreachable 来自目的地本身，保留真实地址不动。引用报文必须是客户端**实际发出的
那份**：至少要含 IP 头 + 8 字节传输头（`buildICMPError` 对更短的引用直接放弃），否则
macOS/XNU 的 `icmp_input` 会按 `bad length` 丢弃——这正是早期 traceroute 全 `*` 的原因。

**逐跳探测（让 traceroute 全路径都进 tun）**：客户端 TTL 2..30 的 UDP 探针不由本设备代答，
也不进 netstack 建流。插件取回该探针的 TTL，用同样 TTL 的独立 UDP socket（`IP_TTL`，同时绑定
`next_hop_dev`）向真实 IP 再发一个 32 字节探针，在 `probes` 表里以探测 socket 的本地端口为键
记录客户端、引用报文和 deadline（1.2s）。真实那一跳回的 ICMP time exceeded 由 `probeReply` 命中后：
1. 给该真实跳分配一个 **段内虚拟地址**（从段尾往下取，跳过已分配给域名的 fake IP，
   同一真实地址复用同一个虚拟地址，上限 256 条）；
2. 用这个虚拟地址做回包源地址、客户端原探针做引用，构造 ICMP time exceeded 注入 tun。

因为源地址始终落在 `ipv4_range` 内，所有探测回包都必然走客户端指向 tun 的那条路由。
该虚拟地址的 PTR 记录返回 `<真实跳地址>.<hop_name_suffix>`（不配置则复用 `table_prefix`），traceroute
因此打印 `192.168.10.1.mosdns (198.19.x.y)`；只返回点分四段会被解析器丢弃，所以必须带
一个域名后缀。

**销毁时机**：探测表项在应答到达时删除，1.2s 超时也删除，5s 周期清扫兜底；虚拟地址视图不随
PTR 应答删除——traceroute 每跳连发几个探针、查名字往往滞后于最后一发，删早了同一个真实跳就会
换号或查不到名字。视图在 `hopViewTTL`（30s）内复用，`hopOf` 命中即续期，`sweepHops` 兜底回收，
所以同一真实跳连续多轮 traceroute 都打印同一个地址。

**验证**
```sh
traceroute 198.18.0.8                      # 第 1 跳 198.18.0.1.<后缀> (198.19.x.y)，之后每跳 <真实IP>.<后缀>
traceroute -n 198.18.0.8                   # -n 不查名字，只看地址是否都在 ipv4_range 内
dig @127.0.0.1 -p 53 -x 198.19.255.253 +short   # 返回 11.10.12.1.<后缀>.
dig @127.0.0.1 -p 53 -x 198.19.255.253 +short   # 再查一次仍返回同一名字（视图保留 30s）
ping -c 3 198.18.0.8                       # 配了代理：本地应答；没配：raw socket 走 next_hop_dev
netstat -s -p icmp                         # messages with bad length 不应再增长
```
反向解析要真正到本插件，客户端必须把 DNS 指向它；只改反向域的做法见下文。

插件在 `Init` 阶段先把 `<prefix>_mapping` 里的关系恢复到内存映射表（domain ↔ fake IP 双向），
之后的数据面查询只读内存，未命中才回查 SQLite 并回填。`use_tun: false` 时还会把 nftables
`fakeip_<prefix>` 的 `dnat_map` 与本地表比对：数据库有、防火墙缺的条目重新下发；防火墙有、
数据库没有的假 IP 记为已占用，避免分配器重复分配（日志 `firewall mapping reconciled`）。


```shell
wget https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat -O /etc/mosdns/rule/geosite.dat
wget https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat -O /etc/mosdns/rule/geoip.dat

```

CN 分级分流（`etc/mosdns/config.yaml` 的 `main`）分两级：域名命中 `geosite:cn` 时先问本地解析器
（`forward_local`），有结果就直接返回真实地址、不再改写；否则问公网（`forward_public`），答案落在
`geoip:cn` 也停，只有真正要出公网的目标才分配 fake IP。第一级用的是 sequence 的 fallback 节点而不是
裸 `forward_local`：本地解析器宕机或慢于 `fast_fallback`（500 ms）时由公网接手，客户端不会拿到空答案；
没有开 `always_standby`，本地正常时不会多发一次公网查询，CN 域名也不会离开本地网络。
### ocserv_ctl
把 DNS 请求的来源地址映射到 ocserv 当前登录用户：源地址命中 `occtl --json show users` 里的
`Remote IP`（客户端公网地址）或 `IPv4`（隧道内地址）时，给查询打上标记（`mark`），供后续
`marker` matcher 使用。
用户列表按 `cache_ttl` 缓存；`occtl` 失败或超时只告警并沿用上一份快照，不阻塞解析。
`socket` 与 `addr` 都不填时插件不启用（不调 occtl、不打标记，查询透传）；socket 尚未创建时也会跳过。
`socket: auto` 会依次探测 `/run/ocserv`、`/var/run/ocserv` 下的 `occtl.socket|occtl.sock|socket`，
用第一个存在的路径并缓存——VyOS 上 socket 路径与上游不同，用 auto 最省事。

除查询链识别外，插件还给 bot 的 `/vpn` 提供运维动作：从 `config_path` 指向的 `ocserv.conf`
解析 `ipv4-network`/`ipv4-netmask` 与 `config-per-user`，把网段首个可用地址留给 tun 服务端，
其余按需分配给用户（写 `explicit-ipv4`，改完 `/vpn reload` 生效）；并通过 `systemctl`
执行 `reload`（保留在线会话）与 `restart`（断开所有会话，可用 `disable_restart: true` 禁用）。
`config-per-user` 在 `auth = "radius[...,groupconfig=true]"` 时不生效，两种方式不要混用。

插件还会建一个 unix socket（`event_socket`）接收 ocserv 上下线钩子推送的事件：钩子每次
connect/disconnect 发一行 JSON，插件校验后写进内存环形缓冲（`event_buffer`，默认 500 条）
并追加到 JSONL（`event_log`），不再逐条给管理员发 Telegram。`/vpn events [n] [user]` 可以回看。
脚本见 `etc/ocserv/ocserv-updown.sh` 与 `etc/ocserv/ocserv_notify.py`。
```yaml
  - tag: ocserv_user
    type: ocserv_ctl
    args:
      socket: auto                       # 或具体路径 / addr: "1.2.3.4:4433"（二选一）
      timeout: 3
      cache_ttl: 15
      mark: 100
      config_path: /etc/ocserv/ocserv.conf
      systemd_unit: ocserv
      systemctl_path: systemctl
      disable_restart: false
      event_socket: /run/mosdns/ocserv-updown.sock
      event_log: /config/ocserv-events.jsonl
      event_buffer: 500
```
### radius
给 ocserv 当 RADIUS 服务端：账号由插件自己存在本地 SQLite，不再从 ocserv 的 `ocpasswd` 读。
ocserv 打开 `auth = radius` 后发 `Access-Request`（PAP），插件校验用户名、密码与启用状态，
通过时把账号的 group 作为 `Class` 属性回给 ocserv；账号配置了固定 IP 时再回
`Framed-IP-Address(8)`，ocserv 每次登录都给该用户同一个隧道地址。打开记账后同时收 `Accounting-Request`，
在 `radius_sessions` 里记录每个会话的起止时间、客户端地址与收发字节。
只实现 PAP：若客户端协商成 EAP-MSCHAPv2，ocserv 发来的是 `CHAP-Password`，插件明确回 Reject
并提示改用 PAP，不会静默丢包。密码按 PBKDF2-HMAC-SHA256（12000 轮加盐）存，明文不落盘；
账号的增删改由 `telegram_bot` 的 `/user` 完成，固定 IP 用 `/user ip <name> <ipv4|->`
设置或清除（`-` 表示回到动态池）。
```yaml
  - tag: radius
    type: radius
    args:
      listen: 0.0.0.0:1812             # 认证端口
      accounting_listen: 0.0.0.0:1813  # 记账端口，off / 0 关闭
      secret: "换成一串随机字符"        # 必填，必须与 ocserv 的 secret 一致
      db_path: etc/mosdns/radius.db    # 账号与会话表
```
老库（`radius_users` 还没有 `ip` 列）在插件启动时自动补列，不需要手工迁移；固定 IP 由
`ip <> ''` 的部分唯一索引约束，同一个地址不能同时绑两个账号。
ocserv 侧对应（版本不同，段名可能是 `radius server` / `radius secret`，以本机 `ocserv.conf` 注释为准）：
```ini
auth = radius
radius[0].server = 127.0.0.1
radius[0].secret = 换成一串随机字符
radius[0].auth = pap
accounting[0].server = 127.0.0.1
accounting[0].secret = 换成一串随机字符
```
### telegram_bot
长轮询 Telegram Bot，用来在没有 SSH 的场合看状态、改配置、跑脚本。启动即开始拉取
`getUpdates`，`token` 缺失或 `chat_ids` 为空时插件保持禁用（不建连、不占线程）。每个 chat 绑定
一个角色，角色决定它能发哪些命令；只列在 `chat_ids` 里的 chat 用 `default_role`（默认 `admin`）。
两个角色是内置的，不必在 `roles` 里声明：`admin` 只能查看状态、管理 RADIUS 用户、查看和操作
ocserv、导出指定用户的访问记录（`status`/`ocserv`/`radius`/`access`）；`superadmin` 拥有全部权限。
常用命令：`/status`、`/net`（数据面观测：tun 设备、代理是否生效、打标与表号、本插件在
`ip rule show` 里的规则、出口表的 default、nft 标记集合大小）、`/ledger`（账本里记了哪些待清理对象）、
`/sweep`（按账本删掉当前配置不拥有的残留，`kill -9` 之后可以手动收尾）、`/diag <domain>`（一次诊断：
假 IP、已学到的真实 IP、出口是代理还是 `next_hop`）、`/fip`（查看或切换 fakeip_nat 的映射，`/fip <tag> <sub>` 指定插件）、
`/vpn`（查 ocserv 在线用户、按网段分配固定 IP、reload/restart 服务、回看上下线事件）、`/user`（增删改 RADIUS 账号、用 `/user ip` 绑定固定 IP、查记账会话）、`/config`（读写 mosdns 配置字段）、`/exec`（跑白名单脚本）、
`/proxy`（读或写 fakeip 的出口代理，`/proxy on <url>` / `/proxy off`，写完要 `/reload confirm`）、
`/help`（只列出当前 chat 有权限执行的命令，并按组隐藏整组；`/help` 本身不受权限限制）、
`/audit`（最近的管理动作：谁在什么时候改了配置或跑了脚本，写 `telegram_bot_audit.log`，只记键路径不记值）、
`/reload`（给进程发关闭信号，靠外部 supervisor 重新拉起）、
`/access <user|ip> [days]`（按 RADIUS 用户（取其记账会话里的地址）或直接给地址，从 fakeip 的访问记录
里取出该地址访问过的域名/真实 IP，生成 `.xlsx` 发回请求的管理员；默认 7 天，最多 365 天）。
`proxy` 可让 API 请求走
HTTP(S)/SOCKS5 代理，`api_base` 便于指向镜像或测试端点。
插件之间通过 `fakeip_tags` / `ocserv_tags` / `radius_tags` 定位目标：列表第一个是默认，
其余用命令的第一个参数点名（如 `/fip <tag> stats`）。这三项是列表，不再接受单值写法。
```yaml
  - tag: tg
    type: telegram_bot
    args:
      token: "123456:ABCDEF"             # @BotFather 给的 token，缺失则不启用
      chat_ids: [123456789]              # 允许交互的 chat，空则不启用
      admins:
        - chat_id: 123456789
          role: superadmin                # 内置：全部权限
        - chat_id: 987654321
          role: admin                     # 内置：状态 + 用户 + ocserv + 访问记录导出
      roles:                              # 自定义角色，可 inherits: [admin] 复用内置角色
        ops:
          allow: [status, fakeip, ocserv]
      default_role: admin                 # 只列在 chat_ids 里的 chat 用这个角色
      fakeip_tags: ["fakeip"]             # /fip 可管理的 fakeip_nat 插件 tag
      ocserv_tags: ["ocserv_user"]        # /vpn 可查询的 ocserv_ctl 插件 tag
      radius_tags: ["radius"]             # /user 可管理的 radius 插件 tag
      config_path: etc/mosdns/config.yaml # /config 改写的文件，留空取 -c 参数
      audit_log: ""                       # 审计日志，留空取配置目录下 telegram_bot_audit.log
      proxy: ""                           # 例如 socks5://127.0.0.1:1080
      api_base: https://api.telegram.org
      poll_timeout: 30
```

## 构建与发布

本地交叉编译：

```bash
go run ./tools/crossbuild                 # 全部目标，版本号取 dev/4.0-<git describe>
go run ./tools/crossbuild -version v4.0.1 # 固定版本号
go run ./tools/crossbuild linux/amd64     # 只编指定目标
```

产物在 `build/`，版本号经 `-ldflags -X main.version` 注入；不传 `-version` 且 git 也无答案时不注入，`main.version` 保持默认 `dev/4.0`。

GitHub Actions：

- `.github/workflows/build.yml`：push `main` / PR / 手动触发。跑 `go vet ./...`、`coremain` + `fakeip_nat` + `telegram_bot` + `tools/crossbuild` 的测试，再做十平台交叉编译，二进制作为 artifact 保留 14 天；手动触发可传 `version`。
- `.github/workflows/release.yml`：push `v*` 标签（或手动触发并给版本号）时触发。标签名即发布版本，原样传给 `tools/crossbuild -version`，随后产出：
  - 十个平台二进制，命名 `mosdns-<版本>-<平台>[-armv6|-armv7|...][.exe]`
  - 源码包 `mosdns-<版本>-src.tar.gz` 与 `mosdns-<版本>-src.zip`：排除 `.git`、`.github`、`.idea`、`build`、`dist`、`release` 以及本地 `*.db*`，解包后顶层是 `mosdns-<版本>/`
  - `SHA256SUMS.txt`
  - 以上全部附加到同名 Release（已存在则 `--clobber` 覆盖上传，重跑安全）
