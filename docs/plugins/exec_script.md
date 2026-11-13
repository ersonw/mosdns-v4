# exec_script

[简体中文](exec_script.cn.md) | English

**Source:** `plugin/executable/exec_script/exec_script.go`

## Arguments

- `script_path` (required): executable to run as `script_path <ip> <qname>`.
- `dedup_ttl` (default 300s): the same IP is executed at most once in this window.
- `async` (default `true`): run the script in a goroutine.

## Behavior

The plugin first calls `next`, then takes every A/AAAA address in the response
and runs the script with the real IP and the question name. When `async` is
false it waits for the script to finish. Deduplication state is kept in memory
only and is lost on restart.

## Admin use

`AdminRun(ctx, ip, domain)` runs the configured script synchronously and
returns its combined output. `telegram_bot` uses it for `/exec`; it can only
run the bound script and cannot inject arbitrary commands.

```yaml
- tag: call_route_script
  type: exec_script
  args:
    script_path: /scripts/add_ocserv_route.sh
    dedup_ttl: 300
```
