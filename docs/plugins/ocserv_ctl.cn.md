[English](ocserv_ctl.md) | 简体中文

# ocserv_ctl
把 DNS 请求的来源地址映射到 ocserv 当前登录用户：源地址命中 `occtl --json show users` 里的
`Remote IP`（客户端公网地址）或 `IPv4`（隧道内地址）时，给查询打上标记（`mark`），供后续
`marker` matcher 使用。
用户列表按 `cache_ttl` 缓存；`occtl` 失败或超时只告警并沿用上一份快照，不阻塞解析。
`socket` 与 `addr` 都不填时插件不启用（不调 occtl、不打标记，查询透传）；socket 尚未创建时也会跳过。
`socket: auto` 会依次探测 `/run/ocserv`、`/var/run/ocserv` 下的 `occtl.socket|occtl.sock|socket`，
用第一个存在的路径并缓存——VyOS 上 socket 路径与上游不同，用 auto 最省事。

除查询链识别外，插件还给 bot 的 `/vpn` 提供运维动作：从 `config_path` 指向的 `ocserv.conf`
解析 `ipv4-network`/`ipv4-netmask` 与 `config-per-user`，把网段首个可用地址留给 tun 服务端，
其余按需分配给用户（写 `explicit-ipv4`，改完 `/vpn reload` 生效）；并通过 `systemctl`
执行 `reload`（保留在线会话）与 `restart`（断开所有会话，可用 `disable_restart: true` 禁用）。
ocserv 1.1.6 里 `config-per-user` / `config-per-group` 要求补充配置来源是 file；如果 `auth` 写了
`groupconfig=true`，补充配置会切到 radius，启动直接报
`specified config-per-user or config-per-group but supplemental config is 'radius'`。要用组/用户
配置文件就删掉 `groupconfig=true`；要让 RADIUS 下发补充配置就删掉 `config-per-*`，二选一。

插件还会建一个 unix socket（`event_socket`）接收 ocserv 上下线钩子推送的事件：钩子每次
connect/disconnect 发一行 JSON，插件校验后写进内存环形缓冲（`event_buffer`，默认 500 条）
并追加到 JSONL（`event_log`；配置了 `event_socket` 但没写 `event_log` 时，默认使用
socket 同目录下的 `ocserv-events.jsonl`），不再逐条给管理员发 Telegram。`/vpn events [n] [user]`
优先从 `event_log` 文件读取，所以进程重启后仍能回看历史；文件不可用时才退回内存缓冲。
脚本见 `etc/ocserv/ocserv-updown.sh` 与 `etc/ocserv/ocserv_notify.py`。
```yaml
  - tag: ocserv_user
    type: ocserv_ctl
    args:
      socket: auto                       # 或具体路径 / addr: "1.2.3.4:4433"（二选一）
      timeout: 3
      cache_ttl: 15
      mark: 100
      config_path: /etc/ocserv/ocserv.conf
      systemd_unit: ocserv
      systemctl_path: systemctl
      disable_restart: false
      event_socket: /run/mosdns/ocserv-updown.sock
      event_log: /run/mosdns/ocserv-events.jsonl
      event_buffer: 500
      timezone: Asia/Shanghai            # 无时间字段的事件按此时区落盘
```
