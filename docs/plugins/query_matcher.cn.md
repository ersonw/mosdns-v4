[English](query_matcher.md) | 简体中文

# query_matcher
- **文件**：`plugin/matcher/query_matcher/query_matcher.go`；注册 `:39`
- **参数**（`:64-71`）：`client_ip[]`、`ecs[]`、`domain[]`、`qtype[]`、`qclass[]`
- **行为**：逐项构建 matcher 后逻辑与（`:88-129`）；**空组 = 不匹配**（`utils.go:119-121`）
- **预置**（`:41-59`）：`_qtype_A_AAAA`（qtype 1,28）、`_qtype_AAAA`（28）、`_query_edns0`（查询带 EDNS0，`:133-139`）
