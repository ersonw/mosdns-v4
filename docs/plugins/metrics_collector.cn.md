[English](metrics_collector.md) | 简体中文

# metrics_collector
- **文件**：`plugin/executable/metrics_collector/collector.go`；注册 `:34`；**无参数**
- **行为**（`:75-89`）：`thread` gauge 进出、`query_total`、`err_total`、`response_latency` 直方图（毫秒）
- **注意**：指标名带 `plugin_<tag>_` 前缀（`register.go:202-204`），因此可以多处放置、互不冲突
