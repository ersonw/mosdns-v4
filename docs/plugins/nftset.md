[简体中文](nftset.cn.md) | English

# nftset

**Source:** `plugin/executable/nftset/nftset.go, nftset_linux.go, nftset_other.go`

## Arguments

`table_family4/6` (`ip`, `ip6`, `inet`), `table_name4/6`, `set_name4/6`, `mask4` (24), `mask6` (32).

## Behavior

Linux only. Collects response IPs as `SetIPElem` and batch-writes them to nftables; failures are warnings only. A family is enabled only when its family/table/set triple is complete. Non-Linux builds are no-ops.

## Presets

None.
