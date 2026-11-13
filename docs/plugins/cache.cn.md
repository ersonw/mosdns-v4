[English](cache.md) | 简体中文

# cache — 查询缓存
- **文件**：`plugin/executable/cache/cache.go`
- **注册**：`:47`；预置 `_default_cache`（`:49`，等价 `Args{}`）
- **参数**（`:61-70`）：`size`、`redis`、`redis_timeout`、`lazy_cache_ttl`、`lazy_cache_reply_ttl`（≤0 → 5s，`:114-116`）、`cache_everything`、`compress_resp`（snappy）、`when_hit`（可执行 tag）
- **行为**（`:156-197`）：
  - 只有「单问题、且无 Answer/Ns/Extra」的简单查询才缓存（`:202-203`），除非 `cache_everything`
  - 命中 → 改 ID、`SetResponse`，若配了 `when_hit` 则执行它（`:176-185`）
  - 过期命中 → 记 `lazy_hit_total`，并后台刷新；同一个 msgKey 用 `singleflight` 去重（`:172-175`、`:267-268`）
  - 未命中 → 走 `next`，拿到响应后落缓存（`:188-196`）
- **指标**：`query_total`、`hit_total`、`lazy_hit_total`、`cache_size`（`:133-152`，前缀 `plugin_<tag>_`）
- **注意**：`_default_cache` 的 `size=0` → 内存缓存退化为 **64 shard × 16 = 约 1024 条**（`pkg/cache/mem_cache/mem_cache.go:52-56`）
