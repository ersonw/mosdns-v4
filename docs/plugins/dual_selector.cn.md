[English](dual_selector.md) | 简体中文

# dual_selector — A/AAAA 互斥
- **文件**：`plugin/executable/dual_selector/dual_selector.go`；注册 `:45`；预置 `_prefer_ipv4`(mode 0)/`_prefer_ipv6`(mode 1)（`:46-51`）
- **参数**：`mode`、`wait_timeout`（毫秒；默认 250ms，`defaultWaitTimeout` 在 `:40`）
- **行为**（`:75-158`）：只处理纯 A 或纯 AAAA 查询；**并行发一条另一族查询**（`:88-120`）：
  - 另一族有记录 → 立即回「本族空答案」（`:134-137`、`:144-147`）
  - 另一族没有 → 采用原查询结果（`:148-150`）
  - 等参考查询超时 → 也采用原查询结果（`:151-155`）
- **注意**：两个分支都用 `qCtx.Copy()`（`:88`、`:124`），因为 `qCtx` 非并发安全
