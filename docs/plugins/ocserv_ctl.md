# ocserv_ctl

[简体中文](ocserv_ctl.cn.md) | English

**Source:** `plugin/executable/ocserv_ctl/ocserv_ctl.go`

## Purpose

Maps a DNS client address to a currently logged-in ocserv user. When the query
source matches `Remote IP` (the client's public address) or `IPv4` (the tunnel
address) from `occtl --json show users`, the plugin adds an optional mark to the
query so later `marker` matchers can route it.

The user snapshot is cached for `cache_ttl`. A failed or timed-out `occtl` call
only logs a warning and keeps the previous snapshot; DNS resolution is never
blocked.

## Arguments

| Key | Meaning |
|---|---|
| `socket` | occtl socket path. `auto` probes `occtl.socket`, `occtl.sock`, `socket` under `/run/ocserv` and `/var/run/ocserv`. |
| `addr` | occtl TCP endpoint (`host:port`). `socket` and `addr` are mutually exclusive. |
| `occtl_path` | Path to `occtl`, default `occtl`. |
| `timeout` | Per-call timeout, default 3s. |
| `cache_ttl` | User-list cache, default 15s. |
| `mark` | Mark added on a match; `0` only logs. |
| `config_path` | `ocserv.conf` used by `/vpn pool` and `/vpn alloc` to read `ipv4-network` and `config-per-user`. |
| `systemd_unit` | Default `ocserv`. |
| `systemctl_path` | Default `systemctl`. |
| `disable_restart` | Disables `/vpn restart`. |
| `event_socket` | Unix socket for ocserv connect/disconnect hooks. Empty disables events. |
| `event_log` | JSONL event log. Defaults to `ocserv-events.jsonl` next to the socket. |
| `event_buffer` | In-memory events, default 500, maximum 5000. |
| `timezone` | Timezone for events without a timestamp, default `Asia/Shanghai`. |

If neither `socket` nor `addr` is set, the plugin stays disabled: it does not
call occtl, does not mark, and passes queries through. A missing socket file is
also skipped.

## Admin actions for `/vpn`

- `AdminPool` prints the tunnel network, reserved server address, free range
  and occupied addresses.
- `AdminAllocIP(user, ip?)` writes `explicit-ipv4` into
  `config-per-user/<user>`. Without an IP it picks the lowest free address.
  The first usable address is reserved for the tun server. User names must
  match `[A-Za-z0-9][A-Za-z0-9._@-]*` to prevent path traversal.
- `AdminReleaseIP` removes only the `explicit-ipv4` line, and deletes the file
  when that was the only key.
- `AdminReload` / `AdminRestart` call `systemctl reload|restart <unit>`.
- `AdminEvents` reads the event log, falling back to the memory ring.

The event socket accepts one JSON object per line with `event`, `user`,
`real_ip`, `vpn_ip`, `vpn_ipv6`, `device`, `group`, `rx_bytes`, `tx_bytes`,
`geo`, `isp`, `as`, `ip_type`, `time`. Invalid events return
`{"ok":false,"error":...}` without stopping the hook.

## Notes

- Put this plugin at the head of a `sequence`; otherwise the mark is too late.
- Parsing follows ocserv 1.1.x JSON keys and also accepts case, space and underscore variants.
- `config-per-user` / `config-per-group` and `groupconfig=true` are mutually exclusive in ocserv 1.1.6. Keep the pair that matches your auth source.

```yaml
- tag: ocserv_user
  type: ocserv_ctl
  args:
    socket: auto
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
    timezone: Asia/Shanghai
```
