[English](edns0_filter.md) | 简体中文

# edns0_filter
- **文件**：`plugin/executable/edns0_filter/filter.go`；注册 `:34`；预置 `_edns0_filter_no_edns0`（`:35`，`NoEDNS`）、`_edns0_filter_ecs_only`（`:38`，仅保留 ECS）
- **参数**（`:43-49`）：`no_edns`、`accept[]`、`discard[]`；优先级 `NoEDNS > accept > discard`（`:44-46`）
- **行为**：只改**查询**的 EDNS0 option（`applyFilter` `:91-126`），不改响应
- **注意**：`accept` / `discard` 都不填时 = 「删掉所有 option 但保留 EDNS0 RR」（`default` 分支 `:119-125`）
