[简体中文](misc_optm.cn.md) | English

# misc_optm

**Source:** `plugin/executable/misc_optm/misc.go`

## Arguments

No `type` registration. Only the preset tag is available.

## Behavior

Rejects non-standard queries (not QUERY, QR=1, multiple questions, non-IN) with `REFUSED` and does not call `next`. Caps query EDNS0 UDP size at 1200. After the response, keeps only same-type A/AAAA answers, shuffles them and restores the question name. Removes padding; if the query had no EDNS0, removes EDNS0 from the response.

## Presets

`_misc_optm`
