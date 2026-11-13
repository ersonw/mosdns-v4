# 配置与运维

[English](usage.md) | 简体中文

## 配置文件

mosdns 只读取一个 YAML 文件，主要段落：

| 键 | 用途 |
|---|---|
| `log` | 日志级别与输出；`debug` 打开逐包日志。 |
| `data_providers` | 可热重载的域名/IP 文件（`v2dat`、文本等）。 |
| `plugins` | 插件实例与 `tag` / `type` / `args`。 |
| `servers` | 入口，把 `exec` 链绑定到监听器。 |
| `api` | 可选 HTTP API。 |

完整注释示例见 [`etc/mosdns/config.yaml`](../etc/mosdns/config.yaml)：开头是可
运行的最小配置，之后逐项说明所有插件字段。参数按 `ErrorUnused: true` 解码，
字段名写错会直接启动失败，必须与示例完全一致。

最小 server 段：

```yaml
servers:
  - exec: main
    listeners:
      - protocol: udp
        addr: 127.0.0.1:1053
```

生产环境一般改成 `0.0.0.0:53` 并以 root 运行，或授予
`CAP_NET_BIND_SERVICE`。需要 TCP DNS 时再加一个 `protocol: tcp` 的监听器。

## 命令行

```bash
mosdns version
mosdns start -c /etc/mosdns/config.yaml -d /etc/mosdns
mosdns service install -c /etc/mosdns/config.yaml -d /etc/mosdns
mosdns service start|stop|restart|status|uninstall
```

`-c` 选择配置文件，`-d` 在解析相对路径前切换工作目录，`--cpu N` 限制
`GOMAXPROCS`。

## 插件链

`servers[].exec` 指向一个 `sequence` tag。链是有序的插件 tag 列表，支持这些
控制节点：

```yaml
- tag: main
  type: sequence
  args:
    exec:
      - _misc_optm
      - cache
      - if: "qtype_A_AAAA && !is_local"
        exec: [fast_forward]
        else_exec: [_return]
```

`_return` 立即结束链。`blackhole` 总是继续走 `next`；要停止请用 `_return`。
每个插件的参数、预置 tag 和短路行为见[全部插件](plugins/README.cn.md)。

## 数据源

`data_providers` 的条目在插件参数里写为 `provider:<tag>:<code>`。文本列表和
v2dat 文件都可以用 `auto_reload: true` 热重载。

`telegram_bot` 的 `/provider` 可以增、改、删、清空或列出数据源域名。`.txt`
数据源支持分页列出，页码和分页大小必须同时提供：

```text
/provider <tag> list <page> <page_size>
```

## 日志

`log.level` 控制详细程度：

- `info`：生命周期和数据面就绪节点。
- `debug`：逐查询、逐 nft 命令、逐包；日志量很大。
- `warn` / `error`：只记录降级路径和失败。

插件日志带插件 tag 前缀。链里放了 `_query_summary` 时，每个查询会打一行
问题、rcode 和耗时。

## 远程运维

`telegram_bot` 把每个 chat 绑定到一个角色：

- `admin`：状态、RADIUS 用户、ocserv、访问记录导出、数据源域名列表，以及
  `/watch` + `/stop`。
- `superadmin`：继承 `admin` 的全部权限，并附加其余所有权限。

chat 只能看到自己角色允许的命令；`/help` 只列出当前可用命令。
`fakeip_tags`、`ocserv_tags`、`radius_tags` 是数组，第一个是默认目标，命令
可以用第一个参数点名其它目标。

`/watch [tag] <source_ip>` 持续编辑同一条消息，显示该源 IP 最新 20 条记录：
目的地址、域名、协议和端口。TUN 模式直接抓包，并同时轮询
`conntrack -L -s <ip>` 作为兜底；非 TUN 的 fakeip 模式只使用该轮询。`/stop`
停止当前 chat 的全部监听会话。

`/reload confirm` 校验配置后以非零码退出，必须由外部 supervisor 重新拉起。
`telegram_bot` 会为 config、proxy、sweep、provider、reload、exec、fip 动作
写审计日志。

## 平台说明

- Linux 支持完整的 nftables NAT、`ip rule` 打标路由和 TUN。
- macOS 使用 utun 和单一路由表，`next_hop` 在该平台不生效。
- FreeBSD 使用 `/dev/tun<N>`；Windows 使用 Wintun，需要 `wintun.dll`。
- 所有 TUN 模式都需要 root/管理员权限。

## 排障

1. 先把 `log.level` 调到 `debug`，看第一条 `error`。
2. 启动前确认数据源文件存在。
3. 数据面启用后检查 `nft list tables`、`ip rule show`、
   `ip route show table <n>`。
4. 用 `telegram_bot` 的 `/net`、`/ledger`、`/diag`、`/sweep` 检查 fake-IP
   数据面。
5. 插件初始化失败时日志会给出 tag 和参数；未知参数按设计会启动失败。

## 相关文档

- [安装与运行](install.cn.md)
- [全部插件](plugins/README.cn.md)
- [授权说明](licensing.cn.md)
