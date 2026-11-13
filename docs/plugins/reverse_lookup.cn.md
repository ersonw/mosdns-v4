[English](reverse_lookup.md) | 简体中文

# reverse_lookup
- **文件**：`plugin/executable/reverse_lookup/reverse_lookup.go`；注册 `:45`
- **参数**（`:50-55`）：`size`(64k)、`redis`、`handle_ptr`、`ttl`(1800)
- **行为**（`:106-118`）：查询是 PTR 且 `handle_ptr` → 用缓存反查并**直接应答**；否则跑 `next`，再用响应里的 IP 建映射
- **HTTP API**：实现 `ServeHTTP`（`:124`），自动挂在 `/plugins/<tag>/`，`?ip=x.x.x.x` 查询
- **注意**：这是全仓唯一走插件 HTTP API 的插件
