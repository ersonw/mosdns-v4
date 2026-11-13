[English](blackhole.md) | 简体中文

# blackhole — 黑洞 / 指定应答
- **文件**：`plugin/executable/blackhole/blackhole.go`；注册 `:36`；参数（`:62-66`）：`ipv4[]`、`ipv6[]`、`rcode`
- **行为**（`:107-158`）：A/AAAA 有配 IP → 直接答这些 IP（TTL 硬编码 3600）；否则 `rcode >= 0` 用 `GenEmptyReply` 造空响应，`rcode < 0` 则 `SetResponse(nil)`（`:153-158`）
- **预置**（`:38-49`）：`_drop_response`(rcode=-1)、`_new_empty_response`(0)、`_new_servfail_response`(2)、`_new_nxdomain_response`(3)
- **注意**：`Exec` 永远不返回 error，且**无条件会调 `next`**（`:102-105`）。所以 `_drop_response` **不是丢包**：它只是把响应置空然后继续走链；若最终仍无响应，入口会兜底成 **SERVFAIL**（`pkg/server/dns_handler/entry_handler.go:118-122`）。真正想「到此为止」请用 `_return`。
