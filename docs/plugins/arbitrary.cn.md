[English](arbitrary.md) | 简体中文

# arbitrary — 内联 zone
- **文件**：`plugin/executable/arbitrary/arbitrary.go`；注册 `:35`；参数 `rr[]`（每项是一段 zone 文本）
- **行为**：用 `pkg/zone_file` 建索引（`:57-71`），命中 `Reply` 就短路（`:49-55`）
- **注意**：`Init` 里 TODO 明确写了暂不支持 data_provider（`:61`），规则只能内联、不能热重载
