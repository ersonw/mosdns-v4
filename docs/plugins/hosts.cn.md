[English](hosts.md) | 简体中文

# hosts
- **文件**：`plugin/executable/hosts/hosts.go`；注册 `:35`；参数 `hosts[]`（文件路径，走 data_provider 热重载）
- **行为**：默认 `MatcherFull`（`:55`、`:63`）；`Exec` 用 `LookupMsg` 命中就**短路返回**（`:79-87`）
