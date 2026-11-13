[简体中文](metrics_collector.cn.md) | English

# metrics_collector

**Source:** `plugin/executable/metrics_collector/collector.go`

## Arguments

None.

## Behavior

Records `thread` gauge, `query_total`, `err_total`, and a `response_latency` histogram in milliseconds. Metric names carry the `plugin_<tag>_` prefix, so the plugin can be placed more than once.

## Presets

None.
