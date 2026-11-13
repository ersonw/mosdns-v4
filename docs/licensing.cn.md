# 授权与第三方声明

[English](licensing.md) | 简体中文

## 项目授权

本仓库是 [mosdns v4](https://github.com/IrineSistiana/mosdns) 的非官方魔改版，
按 **GPL-3.0-or-later** 分发。完整授权原文见 [`LICENSE`](../LICENSE)。

上游项目同样为 GPL-3.0-or-later，原始代码版权归上游作者所有。本分支与上游
没有隶属、赞助或背书关系。

版权归属与非官方声明以 [`NOTICE`](../NOTICE) 为准，其中包含：

- 本分支的版权行；
- 上游仓库链接；
- “本仓库不是官方 mosdns 仓库”的声明；
- GPL-3.0-or-later 授权声明。

## 第三方组件

Release 二进制链接了多种授权的 Go 模块。完整清单见
[`THIRD_PARTY_LICENSES.md`](../THIRD_PARTY_LICENSES.md)，共 67 个运行时模块，
逐项列出模块路径、版本、授权和备注。

授权与公告原文在 [`third_party/licenses/`](../third_party/licenses/) 下。目录名
格式为 `<模块路径下划线化>@<版本>/`，内含该模块的 `LICENSE`、`COPYING` 或
`NOTICE`。格式和更新流程见
[`third_party/licenses/README.md`](../third_party/licenses/README.md)。

运行时集合中的授权类型包括：

- **GPL-3.0 / GPL-3.0-or-later**：主项目和若干上游组件。
- **Apache-2.0**：`dnsproxy`、`nftables`、`btree`、`gvisor`、Prometheus 客户端、
  `spf13/afero`、`spf13/cobra`、`gopkg.in/ini.v1` 等。带 `NOTICE` 的组件必须
  保留公告文件。
- **MIT**：多个小型工具模块。
- **BSD-2-Clause / BSD-3-Clause**：`magiconair/properties`、
  `redis/go-redis/v9` 等。
- **MPL-2.0**：`github.com/hashicorp/hcl`；修改过的 MPL 文件按文件级 copyleft
  处理。
- **Unlicense**：`github.com/AdguardTeam/golibs`、`ameshkov/dnscrypt/v2`、
  `ameshkov/dnsstamps`。
- **Zlib**：`github.com/kardianos/service`。
- **MIT / Apache-2.0 双授权**：`gopkg.in/yaml.v3`，可任选其一。

### 替换模块

`github.com/nadoo/ipset` 被
`github.com/IrineSistiana/ipset v0.5.1-0.20220703061533-6e0fc3b04c0a` 替换，
根授权为 **GPL-3.0**，清单中已单独标注。本分支声明为 GPL-3.0-or-later；
再分发前应自行复核组合作品的授权兼容性。

## 再分发必须保留

分发二进制或修改后的源码时：

1. 保留 [`LICENSE`](../LICENSE) 与 [`NOTICE`](../NOTICE)。
2. 保留 [`THIRD_PARTY_LICENSES.md`](../THIRD_PARTY_LICENSES.md) 以及
   [`third_party/licenses/`](../third_party/licenses/) 下对应文件。
3. 组件提供 Apache-2.0 `NOTICE` 时一并保留。
4. 按 GPL-3.0-or-later 要求提供对应源码。
5. 不得暗示本构建是官方 mosdns 发布。

## 新增或更新依赖

修改 `go.mod` 后：

```bash
go list -m -json all
go list -deps ./...
```

重新生成运行时模块集合，复制新的授权文件，更新清单，再跑一次发布构建。
不要直接改复制下来的授权原文；应从模块源码重新复制。
