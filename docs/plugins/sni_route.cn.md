# sni_route

[English](sni_route.md) | 简体中文

**源码：** `plugin/executable/sni_route/`

## 概述

`sni_route` 在一个指定网卡的入口上拦截 TCP 连接，读取 TLS ClientHello 里的
`server_name`，再按域名后缀选择出口。它解决的是「客户端根本不问本机 DNS」的
场景：App 自带 HTTPDNS、或者用 iCloud 私密代理的加密 DNS 隧道拿到真实 IP，
fakeip 没有机会介入，但 TLS 握手的第一个包里域名仍然是明文。

数据路径：

```text
nftables prerouting (iifname + 可选源地址 + 可选目的地址排除)
  -> meta mark
  -> ip rule fwmark -> route table -> tun_dev
  -> gVisor TCP 栈终止连接
  -> 读 ClientHello，解析 SNI
  -> 命中 query_matcher / domain_file -> egress
  -> 未命中 -> 不选出口，直连交回系统路由处理
  -> 把已读的字节写回远端，然后双向透传
```

只处理 TCP。QUIC 的 SNI 不在明文里，打开 `block_quic` 会在被拦截的客户端上
丢弃 UDP/443，让应用回落到 TCP；默认关闭。

## 配置

```yaml
- tag: sni_tiktok
  type: sni_route
  args:
    interface: eth1
    source:
      - 192.168.10.22/32        # 只拦这台 iPhone；不填默认 0.0.0.0/0
    domain:
      - match_tiktok_site       # 直接复用已有的 query_matcher，多个为 OR
    block_quic: true
    egress: egress_sg           # 命中的流量走这个 egress_route 出口
    bypass_ip:
      - provider:geoip:cn       # 国内目的地址不拦截，保持原来的直连路径
```

`domain` 里写的是 `query_matcher` 插件 tag，不是域名后缀；后缀/provider
统一由那个 matcher 决定，避免配置两套域名表。`domain` 必须在
`sni_route` 之前声明。`domain_file` 仍保留为可选的后缀文件，和 matcher 同时
生效。

命中出口拿到的是 `域名:端口`，由代理侧解析；直连出口拿到的是真实目的 IP，避免把
域名又交回本机解析成 fake IP。未命中没有默认出口可借，直接走系统路由。

`bypass` 里的私有网段、TUN 地址、`198.16.0.0/15` 与 `198.18.0.0/15` 两个
fakeip 段总是排除，不需要重复填写。`bypass_ip` 接受
`response_matcher` 的 `ip` 写法，包括 `provider:<tag>:<category>`。

## 参数

| 参数 | 默认值 | 说明 |
|---|---|---|
| `interface` | `eth0` | 拦截入口网卡。 |
| `source` | `0.0.0.0/0` | 客户端地址或 CIDR；不填表示该网卡全部客户端。 |
| `ports` | `[443]` | 拦截的 TCP 端口。 |
| `domain` | 空 | `query_matcher` 插件 tag 列表，多个为 OR；`*.` 后缀写法不在这里使用。 |
| `domain_file` | 空 | 每行一个后缀，文件变化后自动重载。 |
| `block_quic` | `false` | 丢弃被拦截客户端的 UDP/443。 |
| `egress` | 空 | 命中流量的出口插件 tag。 |
| `tun_dev` | `sn0` | TUN 设备名。 |
| `tun_addr` | `192.0.2.2/32` | TUN 地址，必须是 IPv4 /32。 |
| `tun_mtu` | `1400` | TUN MTU。 |
| `nft_table` | `sni_route` | nft 表名。 |
| `mark` | `130` | 拦截标记，必须与现用标记不冲突。 |
| `route_table` | `130` | 专用路由表。 |
| `route_rule_priority` | `1100` | `ip rule` 优先级。 |
| `bypass` | 空 | 额外排除的目的前缀。 |
| `bypass_ip` | 空 | 额外排除的目的前缀，支持 provider。 |

## 注意

- 只支持 Linux，且需要 root（TUN、nft、ip rule）。
- 插件启动失败只禁用自身，不会让 DNS 服务退出；配置错误仍在初始化时直接失败。
- 一个实例一套 `nft_table`/`mark`/`route_table`/`tun_dev`，多实例必须各用各的。
- 命中判断只看 SNI；ECH 或没有 SNI 的连接按未命中处理，字节透传。
