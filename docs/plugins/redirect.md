[简体中文](redirect.cn.md) | English

# redirect

**Source:** `plugin/executable/redirect/redirect.go`

## Arguments

`rule[]`: each rule has exactly two fields, `original_domain target_domain`.

## Behavior

On a match it rewrites `Question[0].Name`, calls `next`, then restores the question and answer names in the response. It changes the name only, not QType.

## Presets

None.

## Notes

`rule` supports `data_provider` hot reload.
