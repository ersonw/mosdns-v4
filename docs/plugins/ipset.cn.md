[English](ipset.md) | 简体中文

# ipset（仅 linux 写入）
- **文件**：`plugin/executable/ipset/{ipset.go,ipset_linux.go,ipset_other.go}`；注册 `:29`；参数 `set_name4/set_name6`、`mask4`(24)、`mask6`(32)
- **行为**：linux 下**后置**把响应里的 A/AAAA 写进 ipset（`:64-112`），失败只打 warn
- **非 linux**：`ipset_other.go:39-41` 只透传 `next`，**不做任何事且不报错**
