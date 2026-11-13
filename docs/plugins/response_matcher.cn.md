[English](response_matcher.md) | 简体中文

# response_matcher
- **文件**：`plugin/matcher/response_matcher/response_matcher.go`；注册 `:38`
- **参数**（`:47-51`）：`rcode[]`、`ip[]`、`cname[]`
- **行为**：RCode 匹配、答案 IP 匹配、CNAME 匹配，三者逻辑与（`:68-99`）
- **预置** `_response_valid_answer`（`:40`）：答案里存在与问题完全对应（name/qtype/qclass 三元组相等）的记录（`:107-132`）——**只要求「有一个有效答案」，不看 rcode**
