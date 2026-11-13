[English](ecs.md) | 简体中文

# ecs — Client Subnet
- **文件**：`plugin/executable/ecs/ecs.go`；注册 `:37`；预置 `_no_ecs`（`:39`，等价「查询和响应都剥掉 ECS」，`:205-217`）
- **参数**（`:46-61`）：`auto`（用客户端地址）、`force_overwrite`、`mask4`(24)、`mask6`(48)、`ipv4`、`ipv6`
- **行为**（`:122-139`）：加 ECS → `next` → 回包时按情况剥：升级了 EDNS0 就整体移除 EDNS0，只是新增 ECS 就只删 ECS
- **注意**：`auto=true` 时预置 IP 不生效（`:47-49` 注释 + `:155`）
