# 安装与运行

[English](install.md) | 简体中文

## 下载

Release 资产名固定，最新版始终可以用同一地址下载：

```bash
curl -fL -o /tmp/mosdns \
  https://github.com/ersonw/mosdns-v4/releases/latest/download/mosdns-linux-amd64
```

| 平台 | 资产 |
|---|---|
| Linux amd64 | `mosdns-linux-amd64` |
| Linux arm64 | `mosdns-linux-arm64` |
| Linux armv6 / armv7 | `mosdns-linux-armv6`、`mosdns-linux-armv7` |
| Linux 386 / ppc64le | `mosdns-linux-386`、`mosdns-linux-ppc64le` |
| macOS arm64 / amd64 | `mosdns-darwin-arm64`、`mosdns-darwin-amd64` |
| FreeBSD amd64 | `mosdns-freebsd-amd64` |
| Windows amd64 | `mosdns-windows-amd64.exe` |

## 校验

```bash
curl -fL -O \
  https://github.com/ersonw/mosdns-v4/releases/latest/download/SHA256SUMS.txt
sha256sum -c --ignore-missing SHA256SUMS.txt
```

macOS 使用 `shasum -a 256 -c --ignore-missing SHA256SUMS.txt`。校验文件列出
所有资产，`--ignore-missing` 只校验已下载的文件。

## 安装

```bash
sudo install -m 755 /tmp/mosdns /usr/local/bin/mosdns
mosdns version
```

二进制以 `CGO_ENABLED=0` 静态链接，没有运行时库依赖。只支持原生安装，本分支
不提供 Docker 镜像。

## 配置

```bash
sudo mkdir -p /etc/mosdns
sudo curl -fL -o /etc/mosdns/config.yaml \
  https://raw.githubusercontent.com/ersonw/mosdns-v4/main/etc/mosdns/config.yaml
```

示例配置包含完整注释的插件集。启动前至少检查：

- `log.level`
- `servers[].exec`
- `data_providers` 路径
- `fakeip_nat.ipv4_range` 与 `next_hop`
- `telegram_bot.token` 与 `chat_ids`

`telegram_bot` 和 ocserv 使用的可选脚本：

```bash
sudo curl -fL -o /etc/mosdns/domain_manage.py \
  https://raw.githubusercontent.com/ersonw/mosdns-v4/main/etc/mosdns/domain_manage.py
sudo curl -fL -o /etc/mosdns/txt2dat.py \
  https://raw.githubusercontent.com/ersonw/mosdns-v4/main/etc/mosdns/txt2dat.py
sudo chmod +x /etc/mosdns/domain_manage.py /etc/mosdns/txt2dat.py
```

ocserv 上下线钩子：

```bash
sudo mkdir -p /etc/ocserv
sudo curl -fL -o /etc/ocserv/ocserv-updown.sh \
  https://raw.githubusercontent.com/ersonw/mosdns-v4/main/etc/ocserv/ocserv-updown.sh
sudo curl -fL -o /etc/ocserv/ocserv_notify.py \
  https://raw.githubusercontent.com/ersonw/mosdns-v4/main/etc/ocserv/ocserv_notify.py
sudo chmod +x /etc/ocserv/ocserv-updown.sh /etc/ocserv/ocserv_notify.py
```

VyOS 上把钩子复制到 op-mode 目录并重启 ocserv：

```bash
sudo install -m 755 /etc/ocserv/ocserv-updown.sh \
  /usr/libexec/vyos/op_mode/ocserv-updown-script.sh
sudo install -m 755 /etc/ocserv/ocserv_notify.py \
  /usr/libexec/vyos/op_mode/ocserv_notify.py
sudo systemctl restart ocserv
```

## 运行

前台运行：

```bash
sudo mosdns start -c /etc/mosdns/config.yaml -d /etc/mosdns
```

注册为服务（`kardianos/service` 支持 systemd、launchd 和 Windows 服务）：

```bash
sudo mosdns service install -c /etc/mosdns/config.yaml -d /etc/mosdns
sudo mosdns service start
sudo mosdns service status
```

`-d` 在读取相对路径前切换工作目录，`-c` 指定配置文件；两者会传给安装后的服务。

停止或卸载：

```bash
sudo mosdns service stop
sudo mosdns service uninstall
```

## 权限与平台

- `fakeip_nat` 的 `use_tun: true` 会创建 TUN 设备、修改路由和 nftables，需要
  root 或管理员权限。
- Windows 需要把 `wintun.dll` 放在 `mosdns.exe` 旁边。
- 只有 Linux 支持 `ip rule` / 目的地址打标和完整的 nftables 数据面。macOS 使用
  utun 和单一路由表；FreeBSD、Windows 使用各自的 TUN 实现。
- 建议配置进程守护。`telegram_bot` 的 `/reload confirm` 以非零码退出，依赖
  systemd、launchd 或 GoLand 重新拉起。

## 相关文档

- [配置与运维](usage.cn.md)
- [从源码编译](build.cn.md)
- [授权说明](licensing.cn.md)
