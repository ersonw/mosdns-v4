# mosdns-v4

**[mosdns](https://github.com/IrineSistiana/mosdns) 的非官方魔改版。**

本仓库不是上游项目，与上游没有隶属关系，也未获得其背书。它保留上游 v4 插件框架，
并加入本部署使用的 `exec_script`、`fakeip_nat`、`ocserv_ctl`、`radius`、
`telegram_bot` 和发布自动化。

[English](README.md) | 简体中文

## 包含内容

- DNS 转发、缓存、hosts、ECS、EDNS0 过滤与 sequence 路由。
- `fakeip_nat`：通过 nftables NAT 或用户态 TUN 栈实现 fake-IP 映射，可选
  SOCKS5 / HTTP / Trojan / gost 出口。
- `telegram_bot`：基于角色的远程运维，包含 `/watch` 与 `/stop`。
- `ocserv_ctl` 与 `radius`：ocserv 用户映射和本地 RADIUS 服务端。
- `exec_script`：对解析出的地址执行已绑定的脚本。
- 固定命名的 Release 资产，支持 `releases/latest/download/<asset>`。

## 快速开始

```bash
curl -fL -o /tmp/mosdns \
  https://github.com/ersonw/mosdns-v4/releases/latest/download/mosdns-linux-amd64
sudo install -m 755 /tmp/mosdns /usr/local/bin/mosdns
mosdns version

sudo mkdir -p /etc/mosdns
sudo curl -fL -o /etc/mosdns/config.yaml \
  https://raw.githubusercontent.com/ersonw/mosdns-v4/main/etc/mosdns/config.yaml
sudo mosdns start -c /etc/mosdns/config.yaml -d /etc/mosdns
```

其他平台：

```text
https://github.com/ersonw/mosdns-v4/releases/latest/download/mosdns-darwin-arm64
https://github.com/ersonw/mosdns-v4/releases/latest/download/mosdns-darwin-amd64
https://github.com/ersonw/mosdns-v4/releases/latest/download/mosdns-linux-arm64
https://github.com/ersonw/mosdns-v4/releases/latest/download/mosdns-windows-amd64.exe
https://github.com/ersonw/mosdns-v4/releases/latest/download/SHA256SUMS.txt
```

`use_tun` 需要 root/管理员权限；Windows 还需要把 `wintun.dll` 放在二进制旁边。
启用前先读[安装与运行](docs/install.cn.md)。

## 文档

英文是默认语言；每份文档都有 `.cn.md` 后缀的简体中文版本。

| 主题 | English | 简体中文 |
|---|---|---|
| 文档索引 | [docs/README.md](docs/README.md) | [docs/README.cn.md](docs/README.cn.md) |
| 从源码编译 | [docs/build.md](docs/build.md) | [docs/build.cn.md](docs/build.cn.md) |
| 安装与运行 | [docs/install.md](docs/install.md) | [docs/install.cn.md](docs/install.cn.md) |
| 配置与运维 | [docs/usage.md](docs/usage.md) | [docs/usage.cn.md](docs/usage.cn.md) |
| 全部插件 | [docs/plugins/README.md](docs/plugins/README.md) | [docs/plugins/README.cn.md](docs/plugins/README.cn.md) |
| 授权说明 | [docs/licensing.md](docs/licensing.md) | [docs/licensing.cn.md](docs/licensing.cn.md) |

完整注释配置见 [`etc/mosdns/config.yaml`](etc/mosdns/config.yaml)。

## 编译与发布

需要 Go 1.20.x。`release.py` 默认编译全部支持目标；传入目标则只编译指定平台：

```bash
python3 release.py
python3 release.py linux/amd64
python3 release.py linux-amd64 --version v4.0.2
python3 release.py --list
```

推送 `v*` 标签会触发同样的十平台构建，发布固定命名资产和 `SHA256SUMS.txt`。
GitHub 会为标签自动生成源码压缩包。详见[从源码编译](docs/build.cn.md)。

## 授权

本分支按 **GPL-3.0-or-later** 分发；上游项目同样为 GPL-3.0-or-later。
第三方 Go 模块保留各自授权，清单见 [`THIRD_PARTY_LICENSES.md`](THIRD_PARTY_LICENSES.md)，
授权原文在 [`third_party/licenses/`](third_party/licenses/)。

- [`LICENSE`](LICENSE)：GPLv3 全文。
- [`NOTICE`](NOTICE)：版权、上游归属和非官方魔改声明。
- [`docs/licensing.cn.md`](docs/licensing.cn.md)：授权义务与组件说明。

## 上游

- 上游仓库：<https://github.com/IrineSistiana/mosdns>
- 本分支：<https://github.com/ersonw/mosdns-v4>

本分支定制插件的问题请提到本仓库；上游问题请提到上游项目。
