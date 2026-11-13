[English](client_limiter.md) | 简体中文

# client_limiter
- **文件**：`plugin/executable/client_limiter/client_limiter.go`；注册 `:36`
- **参数**：`max_qps`、`v4_mask`(32)、`v6_mask`(48)
- **行为**（`:72-85`）：客户端地址无效直接放过；超限 → `Refused` 且 `GetBadIPObserver().Observe(addr)`
- **注意**：5s 一次的 GC 循环（`:94-105`），`Close` 只关通知 chan
