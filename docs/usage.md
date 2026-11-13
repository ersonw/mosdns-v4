# Configuration and operations

[简体中文](usage.cn.md) | English

## Configuration file

mosdns reads one YAML file. The main sections are:

| Key | Purpose |
|---|---|
| `log` | Log level and output. `debug` enables per-packet logs. |
| `data_providers` | Hot-reloaded domain/IP files (`v2dat`, text, etc.). |
| `plugins` | Plugin instances and their `tag` / `type` / `args`. |
| `servers` | Entry points that bind `exec` chains to listeners. |
| `api` | Optional HTTP API. |

The annotated example is [`etc/mosdns/config.yaml`](../etc/mosdns/config.yaml).
It starts with a minimal working configuration and then documents every plugin
field. Unknown fields fail startup because args are decoded with
`ErrorUnused: true`; keep exact names.

Minimal server block:

```yaml
servers:
  - exec: main
    listeners:
      - protocol: udp
        addr: 127.0.0.1:1053
```

Use `0.0.0.0:53` for production and run as root, or grant
`CAP_NET_BIND_SERVICE`. Add a second listener with `protocol: tcp` when plain
TCP DNS is needed.

## CLI

```bash
mosdns version
mosdns start -c /etc/mosdns/config.yaml -d /etc/mosdns
mosdns service install -c /etc/mosdns/config.yaml -d /etc/mosdns
mosdns service start|stop|restart|status|uninstall
```

`-c` selects the config file and `-d` changes the working directory before
relative paths are resolved. `--cpu N` caps `GOMAXPROCS`.

## Plugin chains

`servers[].exec` points at a `sequence` tag. A chain is an ordered list of
plugin tags, with these control nodes:

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

`_return` stops the chain. `blackhole` always continues to `next`; use
`_return` when you need to stop. See [all plugins](plugins/README.md) for each
plugin's arguments, presets and short-circuit behavior.

## Data providers

`data_providers` entries are referenced from plugin args as
`provider:<tag>:<code>`. Text lists and v2dat files can be hot-reloaded with
`auto_reload: true`.

`telegram_bot` `/provider` can add, modify, delete, clear or list domains in a
provider. For `.txt` providers, `list` supports pagination; page and page size
must be passed together:

```text
/provider <tag> list <page> <page_size>
```

## Logging

`log.level` controls verbosity:

- `info`: lifecycle and data-plane readiness.
- `debug`: per-query, per-nft-command and per-packet detail; high volume.
- `warn` / `error`: degraded paths and failures only.

Plugin logs are prefixed with the plugin tag. `query_summary` logs one line per
query with question, rcode and elapsed time when `_query_summary` is in the
chain.

## Remote operations

`telegram_bot` binds each chat to a role:

- `admin`: status, RADIUS users, ocserv, access export, provider lists and
  `/watch` + `/stop`.
- `superadmin`: inherits all `admin` permissions and adds every remaining
  permission.

The chat sees only commands allowed by its role. `/help` lists the allowed
commands. `fakeip_tags`, `ocserv_tags` and `radius_tags` are arrays; the first
tag is the default target and a command can name another target first.

`/watch [tag] <source_ip>` keeps editing one message with the latest 20 records
for that source IP: destination, domain, protocol and port. TUN mode captures
packets directly and also polls `conntrack -L -s <ip>` as a fallback; non-TUN
fake-IP mode relies on that poll. Domain lookup checks the runtime fake/real
indexes, then names learned from DNS answers, then `<prefix>_real_ips`, and
finally an asynchronous PTR lookup. The learned index obeys `record_ttl`.
`/stop` stops every watch session owned by the current chat.

`/reload confirm` validates the config and exits with a non-zero code; a
supervisor must restart the process. `telegram_bot` writes an audit log for
config, proxy, sweep, provider, reload, exec and fip actions.

## Platform notes

- Linux supports the full nftables NAT plane, `ip rule` mark routing and TUN.
- macOS uses utun and one routing table; `next_hop` has no effect there.
- FreeBSD uses `/dev/tun<N>`; Windows uses Wintun and needs `wintun.dll`.
- All TUN modes need root/administrator rights.

## Troubleshooting

1. Start with `log.level: debug` and check the first `error` line.
2. Verify provider files exist before startup.
3. Check `nft list tables`, `ip rule show` and `ip route show table <n>` when
   the data plane is active.
4. Use `/net`, `/ledger`, `/diag` and `/sweep` from `telegram_bot` for the
   fake-IP data plane.
5. When a plugin fails to initialize, its tag and args are named in the log;
   unknown args fail startup by design.

## Related

- [Install and run](install.md)
- [All plugins](plugins/README.md)
- [Licensing](licensing.md)
