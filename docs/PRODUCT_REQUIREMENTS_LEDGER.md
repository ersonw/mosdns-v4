# mosdns-v4 需求账本

最后更新：2026-11-24

| ID | 需求 / 变更 | 状态 | 证据 |
| --- | --- | --- | --- |
| CBP-001 | CBP 认证失败不能导致整个 mosdns 退出，首次数据拨号再重试 AUTH | 已完成，本地提交 `e9340f1` | `pkg/egress/ErrDeferred`、`plugin/executable/cbp_proxy/manager.go`、`plugin/executable/egress_route/egress_route.go` |
| CBP-002 | CBP outlet 初始化只注册、不触网；bootstrap、NODE_LIST 和 AUTH 等 DNS listener 启动信号后再异步执行，避免 DNS 自依赖 | 已完成，线上生效 | `coremain.Mosdns.ServersStarted`、`plugin/executable/cbp_proxy/startup.go`；VyOS 日志与 TikTok 200 验证 |
| OPS-001 | VyOS SG 出口从 gost 切换为 `cbp_proxy:cbp_aa2:edge-vyos-sg1` | 已完成，线上生效 | `mosdns.service` active、53 端口监听、TikTok 经 `fakeip_tiktok` 返回 200、SG 节点 `sessions=1`、CBP raw tunnel ready |
| CBP-003 | CBP raw ICMP/traceroute 不得在登录完成前打开失败后永久关闭；SNI bypass 必须在真实 relay host 登录后补齐 | 已完成，线上生效 | `fakeip_tiktok` 日志 `tun icmp: cbp raw tunnel ready`；`sni_route` 日志 `proxy bypass added to nft set` |
| CBP-004 | 对齐服务端 `81c5c20` 的 opt-in QUIC data stream：`SessionReady.data_streams`、`DATA_STREAM_OPEN/ACK`、`OpenStreamAuto` 和控制流回退 | 已完成并线上启用 | 线上 `dev/v4.0.0-9-g67c8806`，sha256 `f349d66c7e57509668403b31cd21ee4ced506688c8eb12c9ccae4107d22e3d4c`；`proxy_provides.cbp_aa2.data_streams: true`；日志 `data_streams_supported=true`、`enabled=true`、`available=true`；SG 节点 health `data_streams` 活跃、TikTok 200；设计文档第 31 节 |
| OPS-002 | VyOS HK 出口保持 gost，不在本次切换范围 | 保持现状 | `/etc/mosdns/config.yaml` 的 `egress_hk` |
| DOC-001 | 代码、配置变更同步到 `docs/design/cbp_proxy_provider.md` | 已完成 | 第 30 节 |

约束：

- 代码只提交本地；`git push` 和发布新版本必须等用户明确指示。
- 线上变更前必须保留配置和二进制备份；本次备份为
  `/etc/mosdns/config.yaml.bak.20261124T115751Z` 和
  `/usr/local/bin/mosdns.bak.20261124T115747Z`。
