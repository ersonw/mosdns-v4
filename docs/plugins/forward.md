[简体中文](forward.cn.md) | English

# forward

**Source:** `plugin/executable/forward/forward.go`

## Arguments

`upstream[]` with `addr`, `ip_addr`, `trusted`; `timeout`; `insecure_skip_verify`; `bootstrap`. `trusted` is accepted for compatibility but has no effect.

## Behavior

Tries each upstream in order. It returns an error only after every upstream fails. A successful response still calls `next`.

## Presets

None.

## Example

```yaml
- tag: fwd
  type: forward
  args:
    upstream:
      - addr: "udp://1.1.1.1:53"
    timeout: 5
```
