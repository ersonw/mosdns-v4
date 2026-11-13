[简体中文](blackhole.cn.md) | English

# blackhole

**Source:** `plugin/executable/blackhole/blackhole.go`

## Arguments

`ipv4[]`, `ipv6[]`, `rcode`.

## Behavior

For A/AAAA queries with configured addresses it answers those addresses with a hard-coded TTL of 3600. Otherwise `rcode >= 0` creates an empty reply, and `rcode < 0` calls `SetResponse(nil)`. It always calls `next` and never returns an error.

## Presets

`_drop_response` (rcode=-1), `_new_empty_response` (0), `_new_servfail_response` (2), `_new_nxdomain_response` (3)

## Notes

`_drop_response` does not drop the packet. It clears the response and continues; if nothing answers later, the server entry point turns it into SERVFAIL. Use `_return` to stop a chain.
