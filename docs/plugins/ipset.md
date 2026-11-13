[简体中文](ipset.cn.md) | English

# ipset

**Source:** `plugin/executable/ipset/ipset.go, ipset_linux.go, ipset_other.go`

## Arguments

`set_name4`, `set_name6`, `mask4` (24), `mask6` (32).

## Behavior

Linux only. Post-processing writes response A/AAAA addresses into the configured ipset; failures are warnings only. On other platforms it passes through `next` and does nothing.

## Presets

None.
