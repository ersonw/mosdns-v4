# alias

[English](alias.md) | 简体中文

**源码：** `plugin/executable/alias/alias.go`、`store.go`、`alloc.go`、
`admin.go`、`egress.go`、`stack.go`、`gateway.go`、`tun_linux.go`、
`bind_linux.go`

## 概述

`alias` 在可配置后缀下服务一份域名列表，并在自己的 tun 网卡上承载这些应答之后的流量。它不依赖 `data_provider`，也不包裹或复用 `fakeip_nat`：列表属于插件（`domain_file`），虚拟网段属于插件（`ipv4_range`），出口在数据包到达时才决定，而不是在应答查询时决定。

- `dot_replacement` 不是 `.` 时，只服务压平后的别名。命名顺序是：`replace_suffix` 先去末级标签，`dot_replacement` 再替换剩余的点，最后追加 `suffix`。因此 `ip138.com` 得到 `ip138.local`，`www.ip138.com` 得到 `www-ip138.local`；关闭 `replace_suffix` 时则是 `ip138-com.local`、`www-ip138-com.local`。带点的形式不再应答；子域前缀里已经含替换符时无法唯一反推，会放回原序列；两条记录压平后同名会在启动时直接拒绝。
- 命中列表的 `<真实域名>.<后缀>`（`replace_suffix` 开启时为 `<主干>.<后缀>`）立即用 `ipv4_range` 内的地址应答，查询时不做任何上游解析。
- 发往该虚拟地址的数据包进入插件自己的 TUN，虚拟地址反查到真实域名。有可用代理时把域名直接交给代理、不做解析；无代理时在这一刻解析，并从 `next_hop_dev` 经 `next_hop` 拨出。
- TCP 80 端口由 HTTP 网关终止：客户端明文进，改写 `Host` 后按条目协议（默认 http，可选 https）回源。

## 参数

| 键 | 默认 | 含义 |
|---|---|---|
| `domain_file` | 必填 | 插件自有的列表文件，一行一个 `[scheme://]domain`；条目支持 `https+insecure://`。 |
| `suffix` | `local` | 服务域名的后缀，支持多级。 |
| `replace_suffix` | `false` | `false` 追加（`ip138.com` → `ip138.com.local`）；`true` 先去掉末级标签，再由 `dot_replacement` 处理剩余点，最后追加后缀（`ip138.com` → `ip138.local`，`www.ip138.com` → `www-ip138.local`）。 |
| `alias_mode` | `readable` | `readable` 保留可读别名；`opaque` 用可逆的 base32 编码真实域名（`ip138.com` → `nfydcmzyfzrw63i.aa3.dev`），避免 Chrome 把 `ip138-com.aa3.dev` 识别成 `ip138.com` 的相似域名并弹反钓鱼提示。`opaque` 不能与 `replace_suffix` 同开；超过一个 DNS 标签长度时回退为可读压平名。 |
| `dot_replacement` | `.` | 在 `replace_suffix` 处理之后、追加后缀之前，把剩余域名里的每个点替换成这个字符串。`.` 表示不改；`-` 会把 `ip138.com` 压成 `ip138-com.dyize.com`，与 `replace_suffix: true` 同开时得到 `ip138.dyize.com` / `www-ip138.dyize.com`。不能含点或空白；与 `replace_suffix` 同开时，剩余部分压平后同名会在启动时拒绝。 |
| `ipv4_range` | 必填 | 虚拟 IPv4 网段，至少 `/29`。 |
| `ttl` | `60` | 虚拟 A 记录的 TTL。 |
| `upstream_scheme` | `http` | 无协议条目的默认回源协议：`http`、`https` 或 `auto`。 |
| `add_forwarded_headers` | `false` | 追加 `X-Forwarded-Host`、`X-Forwarded-For` 和 `X-Forwarded-Proto: http`。 |
| `redirect_to_alias` | `false` | 同时应答列表中的真实域名（共用同一个虚拟地址），并让非 alias `Host` 请求以 `302` 跳到 alias 域名，保留原 path 与 query。默认关闭：避免列表抢占其它插件已经在服务的域名。 |
| `tls_cert_file` / `tls_key_file` | 空 | 用于在 443 上终止 TLS 的证书对。配置后 HTTPS 进入同一个网关，跳转使用 `https://<alias>`；不配置时 443 保持字节透传。两个路径必须同时设置。证书必须覆盖所有会经虚拟地址访问 443 的 Host。 |
| `tun_dev` | 空 | 留空自动分配 `lga0..lga63`；指定名称则复用该设备。 |
| `tun_mtu` | 自动 | `0` 自动：直连 1500、有代理 1400；显式值 576..1500。 |
| `proxy` | 空 | `socks5`、`socks5h`、`http`、`https`。 |
| `proxy_insecure` | `false` | `https://` 代理跳过证书校验。 |
| `next_hop` | 空 | 直连出口的网关。 |
| `next_hop_dev` | 空 | 直连出口的网卡；同时用于 socket 绑定。 |
| `route_table` | `100` | 直连出口路由与规则的专用表。 |
| `rule_priority` | `1200` | 选择该表的 `ip rule` 优先级。 |
| `resolver` | 空 | 直连出口解析域名所用的插件 tag。 |

仅 Linux：`stack.go` 使用 gVisor netstack，`tun_linux.go` 负责创建设备；其它平台启动时直接报错。

## DNS 行为

| 查询 | 应答 |
|---|---|
| 命中域名的 A | 返回 `ipv4_range` 中的虚拟地址，TTL 为 `ttl`。 |
| 命中域名的 AAAA | 空应答（`NOERROR`，无记录）。 |
| 命中域名的其它 qtype | 交给后续链。 |
| 未命中 | 交给后续链。 |
| 地址池耗尽 | `SERVFAIL`。 |

插件同时实现 `MatcherPlugin` 与 `ExecutablePlugin`，可单独放在 sequence，也可跟在 matcher 之后。

## 列表文件

一行一个条目，`#` 起注释（整行或行尾），接受 BOM 与 CRLF。`scheme://` 可选，缺省用 `upstream_scheme`。`https+insecure://` 是显式的单条兼容开关，用于证书过期或无法验证的旧源站：仍然使用 TLS，但只对该域名跳过证书与主机名校验；除非通过其他方式确认源站可信，否则不要使用，普通 `https://` 保留完整校验。`auto://` 先尝试 HTTPS，失败再回落 HTTP。只接受纯域名：`domain:`、`full:`、`keyword:`、`regexp:`、`provider:` 前缀、通配符、IP 与路径都会被拒绝。条目会去重；同名条目换协议时更新协议而不是新增一行。列表域名的子域同样被服务，按最长后缀匹配。

每次变更都以原子方式重写文件（临时文件 + `rename`）；`reload` 会丢弃文件里已不再服务的域名的映射。启动和每次 `reload` 后，插件会先把列表中每个域名预分配虚拟地址，并把渲染出的 alias 域名写入运行时 alias 表；子域在首次查询时再分配。DNS 应答和网关跳转都先查映射表：已有映射直接使用，没有才现场分配。

## 数据面

1. 创建或复用设备，应用 MTU 与设备地址，并由地址得到整段的直连路由。
2. TCP 在 netstack 内终止。80 端口进入 HTTP 网关；其它端口按字节透传给 `domain:port`。
3. 代理出口：SOCKS5（CONNECT 传域名，因此 `socks5` 与 `socks5h` 行为一致）、HTTP CONNECT、HTTPS 代理（先与代理完成 TLS）。
4. 直连出口：连接时刻通过 `resolver`（未配置时用系统解析）解析，再以设备地址绑定 `SO_BINDTODEVICE` 拨出。配置 `next_hop`/`next_hop_dev` 时，用专用表加基于源地址的 `ip rule` 固定出口。
5. UDP 在直连出口转发。有代理时故意丢弃 UDP：只支持 TCP 的代理无法承载，直连又会泄漏真实地址；客户端会回落 TCP。
6. 指向已分配虚拟地址的 ICMP echo 由插件本地应答：交换源/目的地址、把类型改成 echo reply、重算 IPv4 头与 ICMP 校验和，直接写回设备。不会发往真实主机；其它 ICMP 类型交给 netstack（丢弃）。内核需开启 `net.ipv4.ip_forward=1`，关闭时插件启动会告警。

## HTTP 网关

开启 `redirect_to_alias` 后，只有 `Host` 是列表中的真实域名（含子域）时才由插件本地回 `302 Found`，`Location: <scheme>://<该真实域名的 alias 域名><path?query>`，不连上游；alias 域名本身和不属于列表的 `Host` 都不跳转，直接进入回源路径。上游对同一个真实域名返回的跳转（典型是 `http://` → `https://`、路径规范化）由网关内部跟随，只把最终响应交给客户端，不会改写成 alias 后再次抛回浏览器。未配置 `tls_cert_file`/`tls_key_file` 时只有 80 上的明文 HTTP 会跳转，443 保持字节透传，真实证书仍然有效；配置证书对后，443 由插件终止 TLS，请求进入同一个网关，跳转 scheme 变为 `https`。证书必须同时覆盖被跳转的真实 Host 和跳转目标 alias 域名；不在证书里的名字会在看到 302 之前就校验失败。

回源时除 `Host` 外，`Origin` 与 `Referer` 中指向 alias 域名的部分也会改写为真实域名（scheme 跟随实际上游是 http 还是 https）；其它浏览器头（`User-Agent`、`Accept`、`Accept-Language`、`Cookie`、`Sec-Fetch-*`、`sec-ch-ua` 等）原样透传，只删除 HTTP 规范要求删除的 hop-by-hop 头。浏览器声明了压缩时，网关只保留自己能解码的 `gzip` / `deflate`，不会凭空增加客户端没声明的压缩格式。

响应方向会继续把客户端留在 alias 命名空间：`Location`、`Content-Location`、`Refresh`、`Link` 中的同站地址，以及 `text/html` 正文里的同站绝对 / 协议相对 URL（含子域），都会改写到对应 alias 域名；外部站点链接保持不变。HTML 正文只处理状态 200、8MiB 以内且可解码的响应；改写后去掉 `Content-Encoding`、`ETag`、`Last-Modified`、`Content-MD5`、`Accept-Ranges`，并重算 `Content-Length`。

带 `Upgrade` 与 `Connection: upgrade` 的请求（WebSocket）按隧道处理：握手保留 `Connection`/`Upgrade` 与 `Sec-WebSocket-*` 字段，`101 Switching Protocols` 原样回给客户端（含 `Sec-WebSocket-Accept`），随后双向透传字节直到任一端关闭。若上游拒绝升级，则按普通响应转发后关闭连接。

网关从已终止的连接中读取 HTTP/1.1 请求，把 `Host` 与请求 URI 改写为真实域名，删除 hop-by-hop 头并发送 `Connection: close`。响应中指向真实域名的 `Location` 会改回 alias 域名，`Set-Cookie` 的 `Domain=` 属性会被去掉，让 cookie 留在 alias 源内。上游失败返回纯文本 `502 Bad Gateway`。

`upstream_scheme: auto` 先尝试 443 的 TLS，失败再回落到 80 的明文 HTTP。

## Bot 命令

`/alias` 通过 `pkg/alias_admin.Admin` 发现已加载的 alias 插件。

| 命令 | 权限 |
|---|---|
| `/alias`、`/alias <tag>`、`/alias <tag> list` | `alias` |
| `/alias <tag> add [scheme://]d`、`del`、`mod`、`clear` | `alias` |
| `/alias <tag> reload` | `alias` |
| `/alias <tag> suffix <s>` | `config` |
| `/alias <tag> range <cidr>` | `config` |

`alias` 属于普通管理员角色，`config` 不属于。`suffix` 运行时生效并写回配置文件；`range` 由插件校验后写入配置文件，需要重启进程：设备地址、分配器与出口规则都要重建。

每次列表变更都会清理受影响域名的状态：虚拟地址、反查映射、插件内解析缓存，以及其它插件为该域名缓存的应答。

## 限制

- 未配置 `tls_cert_file`/`tls_key_file` 时，网关路径要求客户端使用明文 HTTP。客户端若升级到 `https://<alias>`，会收到真实域名的证书，名称校验失败，除非前面另有 TLS 终止。配置证书对后插件自己终止 443，但证书之外的 Host 仍会校验失败。
- 有代理时不承载 UDP，QUIC 会回落到 TCP。
- 只应答 ICMP echo；ICMP 错误与 traceroute 探测不合成，IPv6 虚拟地址未实现。
- 映射仅在内存中，重启后按列表重新预分配；子域在首次查询时分配。
- 网关只处理 80 端口；其它端口的 HTTP 按透明转发处理，不改写 Host。
- `redirect_to_alias` 只有在配置 `tls_cert_file`/`tls_key_file` 后才会对 HTTPS 生效。证书对是插件级全局配置，列表里只要有证书覆盖不到的名字就不要开。
- TLS 终止后的 443 是 HTTP 网关而不是透明转发：该虚拟地址上的非 HTTP TLS 协议不会透传。
- 开启 `redirect_to_alias` 后，列表中精确域名的 A 查询都会回虚拟地址，列表不要与 fakeip/provider 已在服务的域名重叠。
- 网关只内部跟随同域名的 HTTP(S) 跳转；上游跳到其它主机（例如站点自己的 WAF 跳 `127.0.0.1`）仍会原样回给客户端，这是上游行为，不是 alias 循环。
