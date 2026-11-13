[简体中文](arbitrary.cn.md) | English

# arbitrary

**Source:** `plugin/executable/arbitrary/arbitrary.go`

## Arguments

`rr[]`: each item is an inline zone snippet.

## Behavior

Builds an index with `pkg/zone_file`. A matching query is answered and short-circuits the chain.

## Presets

None.

## Notes

Only inline records are supported. `data_provider` hot reload is not implemented.
