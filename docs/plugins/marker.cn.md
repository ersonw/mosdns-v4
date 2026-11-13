[English](marker.md) | 简体中文

# marker — 双重身份
- **文件**：`plugin/executable/marker/marker.go`；注册 `:32`
- **行为**：`Exec` 给 `qCtx` 打一个全局唯一 mark（`:50-53`）；`Match` 判断该 mark 是否存在（`:43-45`）
- **用法**：同一个 tag 既能出现在 `exec` 里当一步，也能出现在 `if` 表达式里当条件
- **注意**：同时声明了 `ExecutablePlugin` 与 `MatcherPlugin`（`:35-36`），所以会被同时放进 `execs` 和 `matchers`

```yaml
- tag: mark_oversea
  type: marker
# 用法：
# exec: [mark_oversea, ...]
# if: "mark_oversea"
```
