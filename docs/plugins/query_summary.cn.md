[English](query_summary.md) | 简体中文

# query_summary（仅预置）
- **文件**：`plugin/executable/query_summary/query_summary.go`；只注册 `_query_summary`（`:36`）
- **行为**（`:49-60+`）：先跑 `next`，再按「问题 + rcode + 耗时」打一行日志
