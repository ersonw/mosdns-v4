# mosdns-v4 Documentation

This repository is an **unofficial, modified fork** of
[mosdns v4](https://github.com/IrineSistiana/mosdns). It keeps the upstream
plugin framework and adds the `exec_script`, `fakeip_nat`, `ocserv_ctl`,
`radius`, `telegram_bot` and release automation used by this project.

The upstream project and its authors retain copyright in the original code.
This fork is not affiliated with or endorsed by upstream. The project is
distributed under **GPL-3.0-or-later**; see [Licensing](licensing.md).

English is the default language. Every document has a Simplified Chinese
counterpart with the `.cn.md` suffix.

## Guides

| Guide | English | 简体中文 |
|---|---|---|
| Build from source | [build.md](build.md) | [build.cn.md](build.cn.md) |
| Install and run | [install.md](install.md) | [install.cn.md](install.cn.md) |
| Configuration and operations | [usage.md](usage.md) | [usage.cn.md](usage.cn.md) |
| Plugins | [plugins/](plugins/) | [plugins/](plugins/) |
| Licensing and third-party notices | [licensing.md](licensing.md) | [licensing.cn.md](licensing.cn.md) |

## Plugin references

All 31 plugin types and preset-only helpers are listed in
[plugins/README.md](plugins/README.md), with individual English and Chinese
cards under `plugins/`.

## Quick start

```bash
curl -fL -o /tmp/mosdns \
  https://github.com/ersonw/mosdns-v4/releases/latest/download/mosdns-linux-amd64
sudo install -m 755 /tmp/mosdns /usr/local/bin/mosdns
mosdns version
sudo mosdns start -c /etc/mosdns/config.yaml -d /etc/mosdns
```

See [Install and run](install.md) for checksums, platform assets and service
management. The full annotated configuration example is
[`etc/mosdns/config.yaml`](../etc/mosdns/config.yaml).
