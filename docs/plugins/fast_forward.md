[简体中文](fast_forward.cn.md) | English

# fast_forward

**Source:** `plugin/executable/fast_forward/fast_forward.go; `udpme.go` for the custom transport`

## Arguments

`upstream[]` with `addr`, `dial_addr`, `trusted`, `socks5`, `so_mark`, `bind_to_device`, `idle_timeout`, `max_conns`, `enable_pipeline`, `enable_http3`, `bootstrap`, `insecure_skip_verify`; `ca[]`.

## Behavior

The first upstream is forced to `trusted` during construction. `Exec` calls `bundled_upstream.ExchangeParallel` and uses the first response. An `addr` starting with `udpme://` uses the built-in `udpmeUpstream`; only this plugin supports that scheme.

## Presets

None.

## Example

```yaml
- tag: fast
  type: fast_forward
  args:
    upstream:
      - addr: "udp://1.1.1.1:53"
      - addr: "tls://1.1.1.1:853"
```
