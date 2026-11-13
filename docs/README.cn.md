# mosdns-v4 文档

本仓库是 [mosdns v4](https://github.com/IrineSistiana/mosdns) 的**非官方魔改版**。
它保留上游插件框架，并加入本项目使用的 `exec_script`、`fakeip_nat`、`ocserv_ctl`、
`radius`、`telegram_bot` 和发布自动化。

上游项目及其作者保留原始代码的版权；本项目与上游没有隶属关系，也未获得其背书。
本项目按 **GPL-3.0-or-later** 分发，详见[授权说明](licensing.cn.md)。

英文是默认语言；每份文档都有 `.cn.md` 后缀的简体中文版本。

## 文档目录

| 文档 | English | 简体中文 |
|---|---|---|
| 从源码编译 | [build.md](build.md) | [build.cn.md](build.cn.md) |
| 安装与运行 | [install.md](install.md) | [install.cn.md](install.cn.md) |
| 配置与运维 | [usage.md](usage.md) | [usage.cn.md](usage.cn.md) |
| 插件 | [plugins/](plugins/) | [plugins/](plugins/) |
| 授权与第三方声明 | [licensing.md](licensing.md) | [licensing.cn.md](licensing.cn.md) |

## 插件文档

全部 31 个插件类型与仅预置 helper 见
[plugins/README.cn.md](plugins/README.cn.md)，单独的英文与中文卡片都在
`plugins/` 下。

## 快速开始

```bash
curl -fL -o /tmp/mosdns \
  https://github.com/ersonw/mosdns-v4/releases/latest/download/mosdns-linux-amd64
sudo install -m 755 /tmp/mosdns /usr/local/bin/mosdns
mosdns version
sudo mosdns start -c /etc/mosdns/config.yaml -d /etc/mosdns
```

校验和、各平台资产与服务管理见[安装与运行](install.cn.md)。完整注释配置见
[`etc/mosdns/config.yaml`](../etc/mosdns/config.yaml)。
