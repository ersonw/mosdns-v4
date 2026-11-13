[简体中文](cache.cn.md) | English

# cache

**Source:** `plugin/executable/cache/cache.go`

## Arguments

`size`, `redis`, `redis_timeout`, `lazy_cache_ttl`, `lazy_cache_reply_ttl` (≤0 becomes 5s), `cache_everything`, `compress_resp` (snappy), `when_hit` (executable tag).

## Behavior

By default only simple single-question queries without Answer/Ns/Extra are cached; `cache_everything` removes that restriction. A hit rewrites the ID, installs the cached response and optionally runs `when_hit`. An expired hit records `lazy_hit_total` and refreshes in the background; the same message key is deduplicated with `singleflight`. A miss calls `next`, then stores the response. Metrics: `query_total`, `hit_total`, `lazy_hit_total`, `cache_size`, prefixed with `plugin_<tag>_`.

## Presets

`_default_cache` (equivalent to empty args)

## Notes

With `size=0`, the memory cache falls back to 64 shards × 16 entries, about 1024 records.
