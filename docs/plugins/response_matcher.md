[简体中文](response_matcher.cn.md) | English

# response_matcher

**Source:** `plugin/matcher/response_matcher/response_matcher.go`

## Arguments

`rcode[]`, `ip[]`, `cname[]`.

## Behavior

Matches RCode, answer IPs and CNAMEs with logical AND.

## Presets

`_response_valid_answer` (at least one answer record whose name/qtype/qclass exactly matches the question; rcode is not checked)
