[简体中文](reverse_lookup.cn.md) | English

# reverse_lookup

**Source:** `plugin/executable/reverse_lookup/reverse_lookup.go`

## Arguments

`size` (64k), `redis`, `handle_ptr`, `ttl` (1800).

## Behavior

A PTR query with `handle_ptr` is answered from the reverse cache. Other queries call `next`, then build an IP-to-name mapping from the response. The plugin also serves HTTP at `/plugins/<tag>/` with `?ip=x.x.x.x`.

## Presets

None.

## Notes

This is the only plugin in the repository that exposes a plugin HTTP API.
