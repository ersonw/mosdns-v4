[简体中文](hosts.cn.md) | English

# hosts

**Source:** `plugin/executable/hosts/hosts.go`

## Arguments

`hosts[]`: file paths, loaded through `data_provider` with hot reload.

## Behavior

Uses full-name matching by default. On a match it replies and short-circuits the chain; it does not call `next`.

## Presets

None.
