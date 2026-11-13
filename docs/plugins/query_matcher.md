[简体中文](query_matcher.cn.md) | English

# query_matcher

**Source:** `plugin/matcher/query_matcher/query_matcher.go`

## Arguments

`client_ip[]`, `ecs[]`, `domain[]`, `qtype[]`, `qclass[]`.

## Behavior

Builds a matcher per non-empty group and combines them with logical AND. An empty group never matches.

## Presets

`_qtype_A_AAAA`, `_qtype_AAAA`, `_query_edns0`
