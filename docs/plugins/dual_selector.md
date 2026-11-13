[简体中文](dual_selector.cn.md) | English

# dual_selector

**Source:** `plugin/executable/dual_selector/dual_selector.go`

## Arguments

`mode`; `wait_timeout` in milliseconds (default 250ms).

## Behavior

Handles only pure A or pure AAAA queries. It sends one query for the other family in parallel. If the other family has records, it returns an empty answer for the current family; otherwise it keeps the original result. A timeout also keeps the original result. Both branches use `qCtx.Copy()` because `qCtx` is not concurrency-safe.

## Presets

`_prefer_ipv4` (mode 0), `_prefer_ipv6` (mode 1)
