[English](sleep.md) | 简体中文

# sleep
- **文件**：`plugin/executable/sleep/sleep.go`；注册 `:36`；预置 `_sleep_500ms`（`:40`）；参数 `duration`（毫秒）
- **行为**：从池里取 timer 等 `duration`，`ctx` 取消会提前返回（`:60-70`）
