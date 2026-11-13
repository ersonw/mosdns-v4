[English](forward.md) | 简体中文

# forward — 顺序多上游
- **文件**：`plugin/executable/forward/forward.go`
- **注册**：`:38`；**参数**（`:49-64`）：`upstream[]{addr, ip_addr, trusted(已废弃)}`、`timeout`、`insecure_skip_verify`、`bootstrap`
- **行为**：`Exec` → `exec`（`:125`）依次尝试上游；全部失败才返回 error；成功后仍会调 `next`
- **注意**：`trusted` 字段保留但无效果（`:61-63` 注释）
