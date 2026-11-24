# mosdns-v4 需求账本

最后更新：2026-11-24

| ID | 需求 / 变更 | 状态 | 证据 |
| --- | --- | --- | --- |
| CBP-001 | CBP 认证失败不能导致整个 mosdns 退出，首次数据拨号再重试 AUTH | 已完成，本地提交 `e9340f1` | `pkg/egress/ErrDeferred`、`plugin/executable/cbp_proxy/manager.go`、`plugin/executable/egress_route/egress_route.go` |
| CBP-002 | CBP outlet 初始化只注册、不触网；bootstrap、NODE_LIST 和 AUTH 等 DNS listener 启动信号后再异步执行，避免 DNS 自依赖 | 已完成，线上生效 | `coremain.Mosdns.ServersStarted`、`plugin/executable/cbp_proxy/startup.go`；VyOS 日志与 TikTok 200 验证 |
| OPS-001 | VyOS SG 出口从 gost 切换为 `cbp_proxy:cbp_aa2:edge-vyos-sg1`；2026-11-24 已回退 gost | 已回退为 `gost://11.10.10.31:1080` | `/etc/mosdns/config.yaml` 的 `egress_sg`；TikTok 经 fakeip 返回 200；`ss` 到 `11.10.10.31:1080` |
| CBP-003 | CBP raw ICMP/traceroute 不得在登录完成前打开失败后永久关闭；SNI bypass 必须在真实 relay host 登录后补齐 | 已完成，线上生效 | `fakeip_tiktok` 日志 `tun icmp: cbp raw tunnel ready`；`sni_route` 日志 `proxy bypass added to nft set` |
| CBP-004 | 对齐服务端 `81c5c20` 的 opt-in QUIC data stream：`SessionReady.data_streams`、`DATA_STREAM_OPEN/ACK`、`OpenStreamAuto` 和控制流回退 | 已完成；当前两个出口已切回 gost，CBP 未启用 | 线上 `dev/v4.0.0-9-g67c8806`，sha256 `f349d66c7e57509668403b31cd21ee4ced506688c8eb12c9ccae4107d22e3d4c`；`proxy_provides.cbp_aa2.data_streams: true`；SG/HK 两路登录均 `data_streams_supported=true`、`enabled=true`、`available=true`；HK 节点 health `data_streams` 活跃、`ipinfo.io` 返回 HK；设计文档第 31/32 节 |
| OPS-002 | VyOS HK 出口从 gost 切换为 `cbp_proxy:cbp_aa2:edge-vyos-hk1`；2026-11-24 已回退 gost | 已回退为 `gost://11.10.10.13:1080` | `/etc/mosdns/config.yaml` 的 `egress_hk`；`ipinfo.io` 经 fakeip 返回 `103.49.60.205`、HK；`ss` 到 `11.10.10.13:1080` |
| OPS-003 | HK CBP 启动依赖：固定 `api.aa2.dev` 到 `/etc/hosts`，并在 mosdns 启动前由 systemd 服务补齐 | 已完成，线上生效 | `/usr/local/sbin/mosdns-bootstrap-hosts`、`mosdns-bootstrap-hosts.service`（enabled）；`/etc/hosts` 含 `104.21.27.123`/`172.67.142.149` |
| CBP-005 | CBP raw ICMP 启动窗口 10s 超时导致 ICMP 永久被丢弃；改为 30s 打开 + 15s 失败重试 | 已完成并部署；当前 gost 出口不使用 CBP raw | 线上 `dev/v4.0.0-14-gaea9390`，sha256 `9e6db65c4fad94875aef7797cc5b0452b97b93c3ba3a89cf16dbd1fc58767c48`；两个 outlet 日志 `tun icmp: cbp raw tunnel ready`；fakeip ping 3/3 回包，未再出现 `dropping echo`；设计文档第 33 节 |
| OPS-004 | VyOS SG/HK 两个出口均切回 gost，保留 CBP provider 配置供以后切回 | 已完成，线上生效 | `egress_sg=gost://11.10.10.31:1080`、`egress_hk=gost://11.10.10.13:1080`；备份 `/etc/mosdns/config.yaml.bak.20261124T1331Z`；`mosdns` active、`NRestarts=0`；103 条 gost ESTAB；设计文档第 34 节 |
| DOC-001 | 代码、配置变更同步到 `docs/design/cbp_proxy_provider.md` | 已完成 | 第 34 节 |

约束：

- 代码只提交本地；`git push` 和发布新版本必须等用户明确指示。
- 线上变更前必须保留配置和二进制备份；本次备份为
  `/etc/mosdns/config.yaml.bak.20261124T115751Z` 和
  `/usr/local/bin/mosdns.bak.20261124T115747Z`。
