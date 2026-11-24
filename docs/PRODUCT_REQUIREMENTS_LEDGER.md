# mosdns-v4 需求账本

最后更新：2026-11-24

| ID | 需求 / 变更 | 状态 | 证据 |
| --- | --- | --- | --- |
| CBP-001 | CBP 认证失败不能导致整个 mosdns 退出，首次数据拨号再重试 AUTH | 已完成，本地提交 `e9340f1` | `pkg/egress/ErrDeferred`、`plugin/executable/cbp_proxy/manager.go`、`plugin/executable/egress_route/egress_route.go` |
| CBP-002 | CBP bootstrap 控制面不得依赖本机 127.0.0.1:53，避免插件初始化阶段 DNS 自依赖 | 已完成，本地提交 `dff9a47`，已部署 | `plugin/executable/cbp_proxy/bootstrap.go` 的 `bootstrapDialContext`；VyOS 线上验证 |
| OPS-001 | VyOS SG 出口从 gost 切换为 `cbp_proxy:cbp_aa2:edge-vyos-sg1` | 已完成，线上生效 | `mosdns.service` active、53 端口监听、TikTok 经 `fakeip_tiktok` 返回 200、SG 节点 `sessions=1` |
| OPS-002 | VyOS HK 出口保持 gost，不在本次切换范围 | 保持现状 | `/etc/mosdns/config.yaml` 的 `egress_hk` |
| DOC-001 | 代码、配置变更同步到 `docs/design/cbp_proxy_provider.md` | 已完成，本地提交 `14accac` | 第 30 节 |

约束：

- 代码只提交本地；`git push` 和发布新版本必须等用户明确指示。
- 线上变更前必须保留配置和二进制备份；本次备份为
  `/etc/mosdns/config.yaml.bak.20261124T094031Z` 和
  `/usr/local/bin/mosdns.bak.20261124T094040Z`。
