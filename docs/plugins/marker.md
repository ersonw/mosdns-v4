[简体中文](marker.cn.md) | English

# marker

**Source:** `plugin/executable/marker/marker.go`

## Arguments

None.

## Behavior

`Exec` adds a unique mark to `qCtx`; `Match` checks whether that mark exists. One tag can be used both as an execution step and as an `if` condition.

## Presets

None.

## Example

```yaml
- tag: mark_oversea
  type: marker
# exec: [mark_oversea, ...]
# if: "mark_oversea"
```
