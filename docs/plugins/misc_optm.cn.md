[English](misc_optm.md) | 简体中文

# misc_optm（仅预置，无 type）
- **文件**：`plugin/executable/misc_optm/misc.go`；常量 `PluginType` 在 `:33` 但**没有** `RegNewPluginFunc`，只注册 `_misc_optm`（`:41`）
- **行为**（`:52-107`）：
  1. 非标准查询（非 QUERY、QR=1、多问题、非 IN）→ 直接 `REFUSED` 且**不走 `next`**（`:55-60`）
  2. 查询 EDNS0 UDP 大小压到 1200（`:63-67`，常量 `maxUDPSize` 在 `:37`）
  3. 响应后：A/AAAA 只留同类型答案并洗牌、改回问题名（`:78-92`）
  4. 响应里删 padding（`:95-97`）；查询没 EDNS0 就删响应 EDNS0（`:100-102`）
