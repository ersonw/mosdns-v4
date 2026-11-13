[English](nftset.md) | 简体中文

# nftset（仅 linux 写入）
- **文件**：`plugin/executable/nftset/{nftset.go,nftset_linux.go,nftset_other.go}`；注册 `:29`
- **参数**（`:34-42`）：`table_family4/6`（`ip`/`ip6`/`inet`）、`table_name4/6`、`set_name4/6`、`mask4`(24)、`mask6`(32)
- **行为**（`:78-138`）：先把响应 IP 收集成 `SetIPElem`，再批量写 nftables；失败只打 warn
- **注意**：任一组三元组（family/table/set）不全就不建该族 handler（`:51-70`）；非 linux 同样为空壳
