[简体中文](edns0_filter.cn.md) | English

# edns0_filter

**Source:** `plugin/executable/edns0_filter/filter.go`

## Arguments

`no_edns`, `accept[]`, `discard[]`. Priority is `NoEDNS > accept > discard`.

## Behavior

Filters EDNS0 options on the query only; the response is not changed. With neither `accept` nor `discard`, it removes all options but keeps the EDNS0 RR.

## Presets

`_edns0_filter_no_edns0`, `_edns0_filter_ecs_only`
