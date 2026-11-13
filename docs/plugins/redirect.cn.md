[English](redirect.md) | 简体中文

# redirect — 域名重写
- **文件**：`plugin/executable/redirect/redirect.go`；注册 `:38`；参数 `rule[]`（每条必须两段：`原域名 目标域名`，`:57-63`）
- **行为**：命中后改 `Question[0].Name`（`:101`），跑 `next`，再把响应里 Question 与 Answer 的名字还原（`:102-113`）
- **注意**：只改域名、不改 QType；`rule` 支持 data_provider 热重载（`:65-80`）
