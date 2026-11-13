[简体中文](client_limiter.cn.md) | English

# client_limiter

**Source:** `plugin/executable/client_limiter/client_limiter.go`

## Arguments

`max_qps`, `v4_mask` (32), `v6_mask` (48).

## Behavior

Invalid client addresses pass through. Over-limit clients get `Refused` and are reported through `GetBadIPObserver().Observe(addr)`. A GC loop runs every 5 seconds; `Close` stops only the notification channel.

## Presets

None.
