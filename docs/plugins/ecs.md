[简体中文](ecs.cn.md) | English

# ecs

**Source:** `plugin/executable/ecs/ecs.go`

## Arguments

`auto`, `force_overwrite`, `mask4` (24), `mask6` (48), `ipv4`, `ipv6`.

## Behavior

Adds an EDNS Client Subnet option, calls `next`, then strips the option from the response. If it had to add EDNS0 it removes the whole EDNS0 record; if ECS was the only addition it removes just the ECS option.

## Presets

`_no_ecs` (strip ECS from query and response)

## Notes

When `auto=true`, the configured `ipv4` / `ipv6` values are ignored.
