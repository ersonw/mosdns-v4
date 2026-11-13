[English](sequence.md) | 简体中文

# sequence — 执行链编译器
- **文件**：`plugin/executable/sequence/sequence.go`
- **注册**：`:33` 类型；`:34` 预置 `_return`
- **参数**：`exec`（`interface{}`，可写字符串 tag / 字符串数组 / `if` / `parallel` / `load_balance` / `primary+secondary`）
- **行为**：`Init` 调 `executable_seq.BuildExecutableLogicTree`（`:54`）编译成链；`Exec` 先跑自己的链、**再跑外层的 `next`**（`:65-71`）
- **`_return`**：`Exec` 直接 `return nil`，不调 `next`（`:79-81`）→ 用它在链中间「到此为止」
- **注意**：编译期就会解析所有 tag，写错立刻启动失败；`sequence` 可以嵌套 `sequence`

```yaml
- tag: main_seq
  type: sequence
  args:
    exec:
      - _misc_optm
      - cache
      - if: "qtype_A_AAAA && !is_local"
        exec: [fast_forward]
        else_exec: [_return]
```
