[English](ttl.md) | 简体中文

# ttl
- **文件**：`plugin/executable/ttl/ttl.go`；注册 `:35`；参数 `maximum_ttl`、`minimal_ttl`
- **行为**：**后置**处理，只改 `qCtx.R()`（`:61-71`）；两个都为 0 时等于什么都不做
