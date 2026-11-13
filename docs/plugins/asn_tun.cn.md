[English](asn_tun.md) | 简体中文

# asn_tun

**源码：** `plugin/executable/asn_tun/*.go`

## 概述

`asn_tun` 把“目的地址属于指定 ASN 所公布 IPv4 网段”的流量送进一个用户态
TUN 栈。它**不分配虚拟 IP**，也**不修改 DNS 答案**：客户端拿到的是真实目的
地址。TUN 中看到的就是真实目的 IPv4，插件用 gVisor netstack 终止 TCP/UDP，
再按“有代理 / 无代理”用真实 `IP:port` 重新出站。

它是 `fakeip_nat` TUN 数据面的“真实目的地”版本：复用已经验证过的代理出口
实现，但 ASN 前缀集合、nftables 打标和 TUN 路由都由本插件自己管理。

## 数据路径

```text
ASN 列表
  -> IPv4 前缀列表（ipverse）
  -> nftables interval set
  -> 目的地过滤（`skip_ip` 命中的包不进入后续流程，未命中的继续）
  -> prerouting 打标（`mirror_dev` 为空时处理全部入口；非空时只处理该入站网卡）
  -> output 打标（仅 `mirror_dev` 为空时安装）
  -> ip rule fwmark <mark> lookup <route_table>
  -> default dev <tun_dev>
  -> gVisor TCP/UDP 栈
  -> 代理（真实目标 IP）或直连出口（真实目标 IP）
```

缓存中的前缀集合在启动时同步加载并写入 nftables，所以重启后首包仍能被正确
打标；随后后台线程再抓取全部 ASN、调用 `cidr_merge.py` 聚合，只有结果变化时
才替换 nft 集合。没有缓存时以空集合启动，等首次异步刷新完成后再开始打标。

## 参数

| 参数 | 默认值 | 说明 |
|---|---|---|
| `asn` | 必填 | 需要加载的 ASN 编号，例如 `[4134, 4837]`。 |
| `source` | `ipverse` | 前缀来源。`ipverse` 从 GitHub 拉取；`bgpq3` 调用本地 `fetch_script` 和 `merge_script`。 |
| `refresh` | `12h` | 周期性刷新间隔；`0` 表示关闭周期刷新，但启动时仍会异步刷新一次。 |
| `cache` | `/config/mosdns/asn_tun_prefixes.json` | 最近一次成功合并后的前缀列表。启动时同步读取并立即建立 nft 集合；异步刷新失败时继续使用缓存。 |
| `fetch_script` | `<配置目录>/scripts/bgpq3_fetch_asn.py` | `source: bgpq3` 时使用的 ASN 前缀抓取脚本；缺失时自动从仓库 raw 链接下载。 |
| `merge_script` | `<配置目录>/scripts/cidr_merge.py` | 抓取全部 ASN 后使用的 CIDR 聚合脚本；缺失时自动下载。 |
| `python` | `python3` | 执行上述脚本的解释器。 |

相对路径按配置文件所在目录解析。脚本缺失时会从
`https://raw.githubusercontent.com/ersonw/mosdns-v4/refs/heads/main/etc/mosdns/scripts/`
下载到 `<配置目录>/scripts/`。脚本本身不需要可执行位，插件通过 `python`
指定的解释器调用。
| `tun_dev` | `asn0` | TUN 设备名，最长 15 个字符。 |
| `tun_addr` | `192.0.2.1/32` | 设备本机 IPv4 地址。它不是客户端可见的虚拟 IP，也不会出现在 DNS 应答中。 |
| `tun_mtu` | `0` | `0` 表示自动：无代理 1500，有代理 1400；范围 576..1500。 |
| `mirror_dev` | 空 | 指定镜像流量的入站网卡。设置后 nft 只处理从该网卡进入的包（`iifname`），并且不安装本机 output 打标链；为空表示全局模式，处理所有入口和本机出站流量。 |
| `skip_ip` | 空 | 目的地地址跳过列表。格式与 `response_matcher` 的 `ip` 字段一致，支持 CIDR、`provider:<tag>` 和 `provider:<tag>:<category>`；命中的目的地不会打 ASN 标记，只有未命中的目的地进入后续 ASN/TUN 流程。 |
| `nft_table` | `asn_tun` | nftables 表名，只允许字母、数字和下划线。 |
| `mark` | `123` | 目标流量使用的 fwmark。 |
| `route_table` | `123` | 存放 `default dev <tun_dev>` 的独立路由表，不能是 `main`。 |
| `route_rule_priority` | `1000` | 入站打标对应的 `ip rule` 优先级，范围 1..32765。 |
| `next_hop` | 空 | 直连出口的网关。 |
| `next_hop_dev` | 空 | 直连出口网卡，同时用于 `SO_BINDTODEVICE`。 |
| `egress_mark` | `mark + 1` | 插件自身直连 socket 使用的 fwmark。 |
| `egress_table` | `124` | 直连 socket 的路由表，内容为 `default via next_hop dev next_hop_dev`。 |
| `proxy` | 空 | `socks5`、`socks5h`、`http`、`https`、`trojan` 或 `gost`，语法与 `fakeip_nat` 相同。 |
| `proxy_insecure` | `false` | 对自签名 `https` / `trojan` 跳过 TLS 校验。 |

没有配置 `proxy` 时，必须提供 `next_hop` 或 `next_hop_dev`，否则插件不知道
自己的直连 socket 从哪里出站。配置了 `proxy` 时会在启动阶段探测；探测失败会
直接报错，不会静默改成直连。

## 运行要求

- Linux，root 或 `CAP_NET_ADMIN`（TUN、nftables、策略路由都需要）。
- 系统存在 `nft`、`ip`、`sysctl`。
- 当前版本仅支持 IPv4。IPv6 前缀不会写入集合；要支持 IPv6，需要给
  netstack 增加 IPv6 协议，并增加 `ip -6` 规则和 IPv6 nft set。

## 关键行为

- `tun_addr` 只是 TUN 设备端点地址，不参与 DNS，也没有 fake IP 映射表。
- `mirror_dev` 用于交换机镜像口/SPAN 的流量：设置后只匹配该网卡的入站包，
  不会再处理本机 `output` 流量；为空时才是全局模式。它不是复制数据包，而是
  把该网卡上收到的镜像副本改道进 TUN，因此该网卡应当是专用镜像口，不能是
  生产流量的入口网卡。
- `skip_ip` 在 nft 层做目的地过滤：命中列表的包不会被打标，也不会进入 TUN；
  只有未命中的包继续走 ASN 流程。它和 `bypass` 的区别是，`bypass` 只保护
  代理服务器/`next_hop` 自身地址，`skip_ip` 是用户可配置的业务跳过列表。
- 代理服务器地址和 `next_hop` 会加入 nft `bypass4` 集合，避免“代理服务器
  本身属于目标 ASN”时被再次打标送回 TUN。
- 被打标的包不能直接送到 `next_hop`，必须进入 TUN；`next_hop` 只服务于
  插件自己的直连 socket，通过 `egress_mark` / `egress_table` 选择。
- 只处理 `meta mark 0` 的包。若系统里已有其他策略先给包打了 mark，本插件
  不会覆盖；需要调整 `route_rule_priority`，或关闭那条冲突策略。
- netstack 当前不处理 ICMP。被打标的 ICMP 在这一版不会代理，也不会转发。
- 底层代理出口不支持 `http` / `trojan` 的 UDP。此类 UDP 流会记录并丢弃；
  `socks5` 可以承载 UDP。

## 配置示例

```yaml
plugins:
  - tag: asn_tun
    type: asn_tun
    args:
      asn: [4134, 4837]
      source: bgpq3
      refresh: 12h
      cache: /config/mosdns/asn_tun_prefixes.json
      fetch_script: scripts/bgpq3_fetch_asn.py
      merge_script: scripts/cidr_merge.py
      python: python3

      tun_dev: asn0
      tun_addr: 192.0.2.1/32
      tun_mtu: 1400
      mirror_dev: ""             # 例如 eth1；空 = 全局
      skip_ip:                   # 不进入 ASN 打标的 destination 列表
        - "provider:geoip:cn"

      nft_table: asn_tun
      mark: 123
      route_table: 123
      route_rule_priority: 1000

      next_hop: 10.0.0.1
      next_hop_dev: eth0
      egress_mark: 124
      egress_table: 124

      # proxy: socks5://user:pass@10.0.0.2:1080
```

本插件是独立的数据面插件，可以只放在 `plugins` 列表里，不必加入 DNS
`sequence`；如果放进 `sequence`，它的 `Exec` 只会把查询原样传递下去。
