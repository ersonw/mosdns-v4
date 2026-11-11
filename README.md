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
      next_hop: "10.131.160.3"
      next_hop_dev: "eth0"
      route_table: "main"       # 默认 main，策略路由可填自定义表名
      route_aggregation: true   # 默认 true，把 /32 host route 严格聚合为 CIDR
```

打开 `use_tun` 后改走 TUN 数据面：插件向系统申请 tun 网卡，把网卡地址设为 `ipv4_range` 的段首地址
（该地址由配置的网段推导，被保留、不会再分配给任何域名），并在主表把整段路由到该网卡，
不再写任何 nft 元素。设备命名按平台不同：Linux 从 `mth0` 起取第一个空闲编号；macOS 的 utun
编号由内核分配（`tun_dev` 留空即可，指定一个已存在的 `utunN` 会被拒绝，因为那是别的进程的设备）；
FreeBSD 取空闲的 `/dev/tun<N>`；Windows 用 Wintun。utun/tun 都是点对点接口，`ifconfig` 必须同时
给出对端地址，插件把对端也填成段首地址（`inet <段首> <段首> netmask 255.255.255.255`），
再由整段路由把流量收进设备。创建网卡在所有平台都需要 root / 管理员权限。
`proxy` 传入 socks5 / http / trojan 链接时作为该数据面的出站代理；探测不通过会回退直连并报错日志。

TUN 数据面没有代理时，出口 socket 需要自己选路：插件新建一张专用路由表（`tun_route_table`，
默认 `100`），写入 `default via <next_hop> dev <next_hop_dev>`，并加一条
`ip rule from <ipv4_range> lookup <table>`，让段内源地址开出的新连接都走这条默认路由，
主机自身的流量不受影响。源地址用段内地址（段首 `.1`，设备已持有该地址），网卡绑定同时生效
（Linux `SO_BINDTODEVICE`、macOS `IP_BOUND_IF`）。`next_hop` 留空时回落系统默认路由的网关/网卡；
两者都留空则完全不建表、不绑源地址，保持原来的直连行为。配了代理时这张表不会创建，
出口就是代理链路（`console` 里可见 `tun egress: proxy carries the outlet`）。
macOS 只有一张路由表、没有 `ip rule`，所以只做源地址 + `next_hop_dev` 网卡绑定；
独立路由表这一步仅在 Linux 生效。
ICMP 也按地址翻译（SNAT）语义处理：`ping` 发往 fake IP 的 echo 请求被转发到真实 IP，
回包把源地址改写回 fake IP；UDP 出口收到的 port unreachable / time exceeded 同样改写后
回给客户端，引用的报文是客户端实际发出的那份（含 IP 头与 UDP 头，短于 IP 头 + 8 字节
传输头的引用会被客户端内核按 bad length 丢弃），源地址保留真实来源。
客户端 TTL 2..30 的 UDP 探针（`traceroute`）不由本设备代答：插件用同样的 TTL 向真实 IP
再探一次，把应答那一跳的真实地址分配为段内一个虚拟地址（从段尾往下取，避开已分配的
fake IP），用这个虚拟地址做回包源地址、客户端原报文做引用回给客户端，所以回包一定落在
客户端发往 tun 的路由范围内。该虚拟地址的反向解析（PTR）返回真实跳地址，`traceroute`
因此显示 `192.168.10.1.mosdns (198.19.255.254)`（加 `.mosdns` 后缀，因为单独的点分四段
不是合法主机名，解析器会丢弃）；前提是客户端把 DNS 指向本插件，否则 PTR 走上游、客户端
只能看到地址。
macOS 客户端不想改全局 DNS 时，只让反向解析走插件即可：

```sh
sudo mkdir -p /etc/resolver
printf 'nameserver 127.0.0.1\nport 53\n' | sudo tee /etc/resolver/in-addr.arpa
sudo killall -HUP mDNSResponder
```

删掉 `/etc/resolver/in-addr.arpa` 即恢复。每个探针一张一次性表项（探测 socket
本地端口 → 客户端 / fake IP / 引用报文），应答到达即删除，1.2s 超时也删除；hop 的虚拟
地址表项保留 30s 供反向解析，过期与 5s 周期清理兜底，不会跨探测累积。出口 socket 报错时即使 raw socket 不可用也会补一条
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
      proxy: "socks5h://user:pass@10.0.0.9:1080"   # 或 http://、https://、trojan://pass@host:443?sni=host
      proxy_insecure: false              # 仅自签证书的 https / trojan 需要打开
      # 无代理时的直连出口：默认路由 = 下一跳 + 下一跳网卡，源地址 = 段内地址
      next_hop: "192.168.1.1"            # 留空则用系统默认路由的网关
      next_hop_dev: "en0"                # 留空则由路由查找决定；填了则同时绑定该网卡
      tun_route_table: 100               # 专用路由表号，仅 Linux 建表
```

TUN 下的假 IP 分配从段内第 2 个地址开始（段首 `.1` 归网卡所有）。升级到该模式前，
请确认 `<prefix>_mapping` 里没有域名正好占着段首地址。

设备同时按主机语义应答 ICMP：段首地址被注册为栈的本地地址，`ping <段首>` 由用户态栈直接回
echo reply；发往段首的 UDP 探针（traceroute 默认用 UDP）回 ICMP port unreachable，所以
`traceroute <段首>` 第 1 跳就显示到达。TTL 为 1 且目标不是段首的包由插件自己构造 ICMP
time exceeded，`traceroute <假 IP>` 因此能把本机显示为第一跳；后面没有真实链路，继续显示超时。
目标既不是段首、又从 `<prefix>_mapping` 查不到真实 IP 时，插件不回任何包（客户端超时），
与真实主机对不可达目标的处理一致。

插件在 `Init` 阶段先把 `<prefix>_mapping` 里的关系恢复到内存映射表（domain ↔ fake IP 双向），
之后的数据面查询只读内存，未命中才回查 SQLite 并回填。`use_tun: false` 时还会把 nftables
`fakeip_<prefix>` 的 `dnat_map` 与本地表比对：数据库有、防火墙缺的条目重新下发；防火墙有、
数据库没有的假 IP 记为已占用，避免分配器重复分配（日志 `firewall mapping reconciled`）。


```shell
wget https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat -O /etc/mosdns/rule/geosite.dat
wget https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat -O /etc/mosdns/rule/geoip.dat

```
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
