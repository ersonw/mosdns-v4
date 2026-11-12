# ADD  

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
      route_mark: 0             # 默认 0 关闭；非 0 表示按目的地址打标分流（见下文，与 use_tun 互斥）
      route_rule_priority: 1000 # 打标模式下那条 ip rule 的优先级，与既有策略规则冲突时调大
      realip: false             # 默认 false（发 fake IP）；true 则不分配假 IP、不做 DNAT，只给真实 IP 写出口路由
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
```

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
- 与 `use_tun` 互斥（tun 自己管整段路由），且仅 Linux 支持，其他平台启动即报错；
- 清理只做三件事：删 `ip rule`、删专用表的 default、删整张 nft 表，不会残留；
- 只对非 tun 数据面生效：`use_tun: true` 时打标整体停用（配置加载阶段会直接拒绝这对组合，
  运行时再拦一次），tun 自己已经接管整段路由；
- 装上后立刻自检并写日志：`route mark: startup check passed`（带 `set` / `set_size` /
  `mark_chains` / `ip_rule` / `default_route` 五个字段）；任一对象缺失则打 Warn
  `route mark: startup check found the mark path incomplete`，不会等到主表被灌满才发现。

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
`marker` matcher 使用。插件不提供 CLI / HTTP 控制面，只在查询链上做识别。
用户列表按 `cache_ttl` 缓存；`occtl` 失败或超时只告警并沿用上一份快照，不阻塞解析。
`socket` 与 `addr` 都不填时插件不启用（不调 occtl、不打标记，查询透传）；配置的 socket 文件尚未创建时也会跳过。
```yaml
  - tag: ocserv_user
    type: ocserv_ctl
    args:
      socket: /run/ocserv/occtl.socket   # 或 addr: "1.2.3.4:4433"（二选一）
      timeout: 3
      cache_ttl: 15
      mark: 100
```
### radius
给 ocserv 当 RADIUS 服务端：账号由插件自己存在本地 SQLite，不再从 ocserv 的 `ocpasswd` 读。
ocserv 打开 `auth = radius` 后发 `Access-Request`（PAP），插件校验用户名、密码与启用状态，
通过时把账号的 group 作为 `Class` 属性回给 ocserv；打开记账后同时收 `Accounting-Request`，
在 `radius_sessions` 里记录每个会话的起止时间、客户端地址与收发字节。
只实现 PAP：若客户端协商成 EAP-MSCHAPv2，ocserv 发来的是 `CHAP-Password`，插件明确回 Reject
并提示改用 PAP，不会静默丢包。密码按 PBKDF2-HMAC-SHA256（12000 轮加盐）存，明文不落盘；
账号的增删改由 `telegram_bot` 的 `/user` 完成。
```yaml
  - tag: radius
    type: radius
    args:
      listen: 0.0.0.0:1812             # 认证端口
      accounting_listen: 0.0.0.0:1813  # 记账端口，off / 0 关闭
      secret: "换成一串随机字符"        # 必填，必须与 ocserv 的 secret 一致
      db_path: etc/mosdns/radius.db    # 账号与会话表
```
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
常用命令：`/status`、`/fip`（查看或切换 fakeip_nat 的映射，`/fip <tag> <sub>` 指定插件）、
`/vpn`（查 ocserv 在线用户）、`/user`（增删改 RADIUS 账号、查记账会话）、`/config`（读写 mosdns 配置字段）、`/exec`（跑白名单脚本）、
`/reload`（给进程发关闭信号，靠外部 supervisor 重新拉起）。`proxy` 可让 API 请求走
HTTP(S)/SOCKS5 代理，`api_base` 便于指向镜像或测试端点。
插件之间通过 `fakeip_tags` / `ocserv_tags` / `radius_tags` 定位目标：列表第一个是默认，
`fakeip_tag` / `ocserv_tag` / `radius_tag` 是旧配置的单值写法，仍兼容。
```yaml
  - tag: tg
    type: telegram_bot
    args:
      token: "123456:ABCDEF"             # @BotFather 给的 token，缺失则不启用
      chat_ids: [123456789]              # 允许交互的 chat，空则不启用
      admins:
        - chat_id: 123456789
          role: admin
      roles:
        admin:
          allow: ["admin"]              # "admin" 表示全部权限；也可用 inherits 组合子角色
      default_role: admin                 # 只列在 chat_ids 里的 chat 用这个角色
      fakeip_tags: ["fakeip"]             # /fip 可管理的 fakeip_nat 插件 tag
      ocserv_tags: ["ocserv_user"]        # /vpn 可查询的 ocserv_ctl 插件 tag
      radius_tags: ["radius"]             # /user 可管理的 radius 插件 tag
      config_path: etc/mosdns/config.yaml # /config 改写的文件，留空取 -c 参数
      proxy: ""                           # 例如 socks5://127.0.0.1:1080
      api_base: https://api.telegram.org
      poll_timeout: 30
```
