[English](padding.md) | 简体中文

# padding（仅预置）
- **文件**：`plugin/executable/padding/padding.go`；三个预置（`:34-42`）
- **行为**：
  - `_pad_query`：查询补到 128 字节；回包时若原查询没有 EDNS0 就删响应 EDNS0、没有 padding 就删响应 padding（`:58-79`）
  - `_enable_conditional_response_padding`：仅在客户端先 pad 时才回 pad（`:89-105`）
  - `_enable_response_padding`：无条件按 468 字节回 pad（预置里 `Always: true`，`:40`；执行分支 `:95-97`）
