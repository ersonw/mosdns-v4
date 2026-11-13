# radius

[简体中文](radius.cn.md) | English

**Source:** `plugin/executable/radius/radius.go`, `radius_packet.go`,
`radius_server.go`, `radius_store.go`

## Purpose

Provides a local RADIUS server for ocserv. Accounts and sessions live in the
plugin's SQLite database, independent of ocserv's `ocpasswd`.

## Arguments

| Key | Meaning |
|---|---|
| `listen` | Authentication listener, default `0.0.0.0:1812`. |
| `accounting_listen` | Accounting listener, default `0.0.0.0:1813`; `off` or `0` disables it. |
| `secret` | Required shared secret; must match ocserv's `radius[0].secret`. |
| `db_path` | SQLite file, default `radius.db`. |
| `ocserv_config` | `ocserv.conf` path; `ipv4-network` is used as the automatic address pool. |
| `ip_pool` | Manual pool override (`CIDR` or `start-end`); takes priority over `ocserv_config`. |
| `timezone` | Display timezone for accounts and sessions, default `Asia/Shanghai`. |

## Authentication

Only PAP is implemented. An `Access-Request` carrying `CHAP-Password` without
`User-Password` is rejected with a message asking for PAP instead of being
dropped. A successful login returns the account group as `Class(25)` and, when
the account has a fixed address, `Framed-IP-Address(8)`. Passwords are stored as
PBKDF2-HMAC-SHA256 with 12,000 rounds and a random salt; plaintext is never
written.

When `ocserv_config` or `ip_pool` defines a pool, new accounts automatically
receive a fixed address from the high end of the pool. The ocserv tun/server
address is reserved and cannot be assigned.

## Accounting and quotas

Implements RFC 2866 `Start(1)`, `Start2(15)`, `Interim(3)`, `Alive(4)` and
`Stop(2)`. `radius_sessions` stores start/end time, client address, byte
counters and `active`. `Acct-Input/Output-Gigawords` are combined with the low
32 bits to avoid 4 GiB wraparound.

Each account keeps `used_in` / `used_out`, optional `max_total` (`0` means
unlimited) and `reset_period` (`0` means never reset). Only the delta of each
session is added, so repeated interim records do not double-count. Reaching
`max_total` disables the account and marks `quota_disabled=1`. A periodic reset
clears usage and re-enables only accounts disabled by quota, including offline
users.

## Storage

`radius_users` has the password hash, group, fixed IP, enabled flag, timestamps,
usage counters and quota fields. Old databases are migrated with `ALTER TABLE`
at startup. A partial unique index on `ip <> ''` prevents one address from
being bound to two accounts. `radius_sessions` stores per-session counters and
`counted_in` / `counted_out` for idempotent accounting.

## Admin interface

`Admin` exposes `Users`, `AddUser`, `DeleteUser`, `SetPassword`, `SetEnabled`,
`SetIP`, `Sessions`, `SetQuota` and `ResetQuota`, plus `SetGroup`. The
`telegram_bot` `/user` command uses these methods.

`Exec` is a pass-through; the plugin does not sit in the DNS chain. It is
discovered through `GetExecutables()` by the bot.

```yaml
- tag: radius
  type: radius
  args:
    listen: 0.0.0.0:1812
    accounting_listen: 0.0.0.0:1813
    secret: "replace-with-a-random-secret"
    db_path: etc/mosdns/radius.db
    ocserv_config: /run/ocserv/ocserv.conf
    # ip_pool: "10.9.0.2-10.9.0.254"
    timezone: Asia/Shanghai
```

ocserv side:

```ini
auth = radius
radius[0].server = 127.0.0.1
radius[0].secret = replace-with-a-random-secret
radius[0].auth = pap
accounting[0].server = 127.0.0.1
accounting[0].secret = replace-with-a-random-secret
```
