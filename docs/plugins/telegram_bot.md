# telegram_bot

[简体中文](telegram_bot.cn.md) | English

**Source:** `plugin/executable/telegram_bot/telegram_bot.go`, `telegram.go`,
`watch.go`, `config.go`, `permissions.go`

## Purpose

Long-polling Telegram bot for operating mosdns without SSH: status, configuration
edits, plugin administration and script execution. If `token` is missing or
`chat_ids` is empty, the plugin stays disabled and does not open a connection.

Each chat is bound to a role. Two roles are built in and do not need to be
declared in `roles`:

- `admin`: status, RADIUS users, ocserv, access-record export, `data_providers`
  domain lists, and `/watch` + `/stop`.
- `superadmin`: inherits every `admin` permission and adds all remaining
  permissions.

A chat listed only in `chat_ids` uses `default_role` (default `admin`).

## Roles and permissions

Permissions: `status`, `fakeip`, `ocserv`, `radius`, `config`, `provider`,
`watch`, `reload`, `exec_script`, `superadmin`. Custom roles can inherit other
roles with `inherits`; effective permissions are the union. Unauthorized chats
are ignored, and an unauthorized command returns
`permission denied: role "x" lacks "y"`.

## Commands

- `/status`, `/plugins`, `/plugin <tag>`, `/perm`
- `/fip [tag] {tags|help|list [n]|get <domain|fake_ip>|add|del|stats|clear confirm}`
- `/watch [tag] <source_ip>`: watch one source IP and keep editing one message
  with the latest 20 destination/domain/protocol/port records. TUN uses packet
  capture plus `conntrack -L -s <ip>` as a fallback; non-TUN fakeip uses the
  conntrack poll alone.
- `/stop`: stops every watch session owned by the current chat.
- `/vpn [tag] {tags|help|users|status|sessions|kick|term|run <occtl args...>|pool|alloc <user> [ip]|free <user>|reload|restart|events [n] [user]}`
- `/user [tag] {tags|help|list|add <name> <pass> [group]|del|pass|enable|disable|group|ip <name> <ipv4|->|limit <name> <max|0|-> [period|0|-]|usage <name>|reset <name>|sessions [active] [n]}`
- `/exec <tag> <ip> <domain>`
- `/config {show|get|set|add|del|validate}`
- `/provider {<tag>|add <domain>|mod <old> <new>|del <domain>|clear|list [<page> <page_size>]}`
- `/reload confirm`
- `/net [tag]`, `/ledger [tag]`, `/sweep [tag] confirm`, `/diag <domain> [tag]`
- `/proxy [tag|on <url>|off]`, `/audit [n]`, `/access <user|ip> [days]`
- `/help`: only lists commands allowed for the current chat.

`/provider` edits `data_providers` entries. For `.txt` providers, `list`
supports pagination; page and page size must be supplied together.

## Configuration management

`/config` edits a `yaml.Node` tree in place, preserving comments and order.
Paths support indexes such as `plugins[1].tag`. `add` merges log keys or
appends to `data_providers`, `plugins`, `servers`, rejecting duplicate tags.
`del` removes by tag, index or log key. `validate` checks tags/types,
`servers[].exec` and listeners before writing. Every write first creates
`<path>.bak.<unixts>`, re-parses the encoded YAML, and only then renames it.

## Auditing and reload

`/config`, `/proxy`, `/sweep`, `/provider`, `/reload`, `/exec` and `/fip`
append one JSON line per action. Values are redacted: config records only key
paths, proxy records only the verb. `/audit` reads the last N lines.

mosdns has no in-process reload: `/reload confirm` validates the configuration
and calls `SendCloseSignal`, exiting with a non-zero code so launchd, systemd or
GoLand can restart the process.

## Plugin targets

`fakeip_tags`, `ocserv_tags` and `radius_tags` are arrays; the first entry is
the default target, and a command can name another target as its first
argument, for example `/fip <tag> stats`.

```yaml
- tag: tg
  type: telegram_bot
  args:
    token: "123456:ABCDEF"
    chat_ids: [123456789]
    admins:
      - chat_id: 123456789
        role: superadmin
      - chat_id: 987654321
        role: admin
    roles:
      ops:
        allow: [status, fakeip, ocserv]
    default_role: admin
    fakeip_tags: ["fakeip"]
    ocserv_tags: ["ocserv_user"]
    radius_tags: ["radius"]
    config_path: etc/mosdns/config.yaml
    domain_manage_script: /etc/mosdns/domain_manage.py
    txt2dat_script: /etc/mosdns/txt2dat.py
    domain_python: python3
    domain_timeout: 30
    audit_log: ""
    proxy: ""
    api_base: https://api.telegram.org
    poll_timeout: 30
    timezone: Asia/Shanghai
```
