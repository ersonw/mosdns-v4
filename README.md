# mosdns-v4

**Unofficial modified fork of [mosdns](https://github.com/IrineSistiana/mosdns).**

This repository is not the upstream project and is not affiliated with or
endorsed by it. It keeps the upstream v4 plugin framework and adds the
`exec_script`, `fakeip_nat`, `asn_tun`, `ocserv_ctl`, `radius`, `telegram_bot` and release
automation used by this deployment.

[简体中文](README.cn.md) | English

## What is included

- DNS forwarding, caching, hosts, ECS, EDNS0 filtering and sequence routing.
- `fakeip_nat`: fake-IP mapping through nftables NAT or a userspace TUN stack,
  with optional SOCKS5 / HTTP / Trojan / gost egress.
- `asn_tun`: mark traffic destined for selected ASN IPv4 prefixes and carry its
  real destination IPs through a userspace TUN stack, with optional proxy or
  direct egress.
- `telegram_bot`: role-based remote operations, including `/watch` and `/stop`.
- `ocserv_ctl` and `radius`: ocserv user mapping and a local RADIUS server.
- `exec_script`: run a bound script for resolved addresses.
- Stable release asset names for `releases/latest/download/<asset>`.

## Quick start

```bash
curl -fL -o /tmp/mosdns \
  https://github.com/ersonw/mosdns-v4/releases/latest/download/mosdns-linux-amd64
sudo install -m 755 /tmp/mosdns /usr/local/bin/mosdns
mosdns version

sudo mkdir -p /etc/mosdns
sudo curl -fL -o /etc/mosdns/config.yaml \
  https://raw.githubusercontent.com/ersonw/mosdns-v4/main/etc/mosdns/config.yaml
sudo mosdns start -c /etc/mosdns/config.yaml -d /etc/mosdns
```

Other platforms:

```text
https://github.com/ersonw/mosdns-v4/releases/latest/download/mosdns-darwin-arm64
https://github.com/ersonw/mosdns-v4/releases/latest/download/mosdns-darwin-amd64
https://github.com/ersonw/mosdns-v4/releases/latest/download/mosdns-linux-arm64
https://github.com/ersonw/mosdns-v4/releases/latest/download/mosdns-windows-amd64.exe
https://github.com/ersonw/mosdns-v4/releases/latest/download/SHA256SUMS.txt
```

`use_tun` needs root/administrator rights. Windows also needs `wintun.dll` next
to the binary. See [Install and run](docs/install.md) before enabling it.

## Documentation

English is the default language. Every document has a Simplified Chinese
counterpart with the `.cn.md` suffix.

| Topic | English | 简体中文 |
|---|---|---|
| Documentation index | [docs/README.md](docs/README.md) | [docs/README.cn.md](docs/README.cn.md) |
| Build from source | [docs/build.md](docs/build.md) | [docs/build.cn.md](docs/build.cn.md) |
| Install and run | [docs/install.md](docs/install.md) | [docs/install.cn.md](docs/install.cn.md) |
| Configuration and operations | [docs/usage.md](docs/usage.md) | [docs/usage.cn.md](docs/usage.cn.md) |
| All plugins | [docs/plugins/README.md](docs/plugins/README.md) | [docs/plugins/README.cn.md](docs/plugins/README.cn.md) |
| Licensing | [docs/licensing.md](docs/licensing.md) | [docs/licensing.cn.md](docs/licensing.cn.md) |

The annotated configuration example is
[`etc/mosdns/config.yaml`](etc/mosdns/config.yaml).

## Build and release

Go 1.20.x is required. `release.py` builds every supported target by default;
target arguments select one or more:

```bash
python3 release.py
python3 release.py linux/amd64
python3 release.py linux-amd64 --version v4.0.2
python3 release.py --list
```

A `v*` tag triggers the same ten-target build and publishes stable-named
assets plus `SHA256SUMS.txt`. GitHub supplies the source archives for the tag.
See [Build from source](docs/build.md) for details.

## License

This fork is distributed under **GPL-3.0-or-later**. The upstream project is
also GPL-3.0-or-later. Third-party Go modules keep their own licenses; the
inventory is in [`THIRD_PARTY_LICENSES.md`](THIRD_PARTY_LICENSES.md), and the
bundled license texts are under [`third_party/licenses/`](third_party/licenses/).

- [`LICENSE`](LICENSE): full GPLv3 text.
- [`NOTICE`](NOTICE): copyright, upstream attribution and the unofficial-fork
  statement.
- [`docs/licensing.md`](docs/licensing.md): obligations and component notes.

## Upstream

- Upstream repository: <https://github.com/IrineSistiana/mosdns>
- This fork: <https://github.com/ersonw/mosdns-v4>

Issues about fork-specific plugins belong here; upstream issues should be
reported to the upstream project.
