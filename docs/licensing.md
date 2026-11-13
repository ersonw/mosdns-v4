# Licensing and third-party notices

[简体中文](licensing.cn.md) | English

## Project license

This repository is an unofficial modified fork of
[mosdns v4](https://github.com/IrineSistiana/mosdns). The fork is distributed
under **GPL-3.0-or-later**. The full license text is in
[`LICENSE`](../LICENSE).

The upstream project is also GPL-3.0-or-later. Upstream authors retain
copyright in the original code. This fork is not affiliated with, sponsored by
or endorsed by upstream.

The authoritative attribution and non-official statement is
[`NOTICE`](../NOTICE). It includes:

- the fork copyright line;
- the upstream repository link;
- a statement that this is not the official mosdns repository;
- the GPL-3.0-or-later declaration.

## Third-party components

The release binaries link Go modules with different licenses. The complete
inventory is [`THIRD_PARTY_LICENSES.md`](../THIRD_PARTY_LICENSES.md). It lists
67 runtime modules with module path, version, license and notes.

Bundled license and notice texts are in
[`third_party/licenses/`](../third_party/licenses/). Each directory is named
`<module_path_with_underscores>@<version>/` and contains the module's
`LICENSE`, `COPYING` or `NOTICE` files. The format and refresh procedure are
described in [`third_party/licenses/README.md`](../third_party/licenses/README.md).

License families in the runtime set include:

- **GPL-3.0 / GPL-3.0-or-later** — the main project and several upstream
  components.
- **Apache-2.0** — `dnsproxy`, `nftables`, `btree`, `gvisor`, Prometheus
  clients, `spf13/afero`, `spf13/cobra`, `gopkg.in/ini.v1` and others.
  Apache-2.0 components require preserving their `NOTICE` files where present.
- **MIT** — many small utility modules.
- **BSD-2-Clause / BSD-3-Clause** — `magiconair/properties`,
  `redis/go-redis/v9` and others.
- **MPL-2.0** — `github.com/hashicorp/hcl`; file-level copyleft applies to
  modified MPL files.
- **Unlicense** — `github.com/AdguardTeam/golibs`, `ameshkov/dnscrypt/v2`,
  `ameshkov/dnsstamps`.
- **Zlib** — `github.com/kardianos/service`.
- **MIT / Apache-2.0 dual** — `gopkg.in/yaml.v3`; either set may be chosen.

### Replacement module

`github.com/nadoo/ipset` is replaced by
`github.com/IrineSistiana/ipset v0.5.1-0.20220703061533-6e0fc3b04c0a`, whose
root license is **GPL-3.0**. The inventory records this explicitly. The fork
declares GPL-3.0-or-later; redistributors should review the combined-work
licensing before publishing a differently licensed build.

## What redistribution must keep

When distributing a binary or a modified source tree:

1. Keep [`LICENSE`](../LICENSE) and [`NOTICE`](../NOTICE).
2. Keep [`THIRD_PARTY_LICENSES.md`](../THIRD_PARTY_LICENSES.md) and the
   corresponding files under [`third_party/licenses/`](../third_party/licenses/).
3. Preserve Apache-2.0 `NOTICE` files where the component provides one.
4. Make the corresponding source available as required by GPL-3.0-or-later.
5. Do not imply that this build is the official mosdns release.

## Adding or updating a dependency

After changing `go.mod`:

```bash
go list -m -json all
go list -deps ./...
```

Regenerate the runtime module union, copy the new license files, update the
inventory, and re-run the release build. Do not edit a copied license text in
place; replace it from the module source.
