# Bundled third-party license texts

This directory contains the license and notice files of the Go modules
linked into `mosdns-v4` release binaries. Each subdirectory is named after
the module path and version that introduced the file:

```text
third_party/licenses/<module_path_with_underscores>@<version>/
```

The authoritative inventory, including license names and special cases, is
[`THIRD_PARTY_LICENSES.md`](../../THIRD_PARTY_LICENSES.md). The top-level
[`LICENSE`](../../LICENSE) and [`NOTICE`](../../NOTICE) cover the project
itself.

To refresh this directory, use `go list -m -json all` together with the
runtime module set of the release targets, copy each module's `LICENSE*`,
`COPYING*` and `NOTICE*` files, and regenerate the inventory. Do not edit a
copied license text; replace it from the module source instead.
