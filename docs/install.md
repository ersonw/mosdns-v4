# Install and run

[简体中文](install.cn.md) | English

## Download

Release assets have stable names, so the latest version is always available
under the same URL:

```bash
curl -fL -o /tmp/mosdns \
  https://github.com/ersonw/mosdns-v4/releases/latest/download/mosdns-linux-amd64
```

| Platform | Asset |
|---|---|
| Linux amd64 | `mosdns-linux-amd64` |
| Linux arm64 | `mosdns-linux-arm64` |
| Linux armv6 / armv7 | `mosdns-linux-armv6`, `mosdns-linux-armv7` |
| Linux 386 / ppc64le | `mosdns-linux-386`, `mosdns-linux-ppc64le` |
| macOS arm64 / amd64 | `mosdns-darwin-arm64`, `mosdns-darwin-amd64` |
| FreeBSD amd64 | `mosdns-freebsd-amd64` |
| Windows amd64 | `mosdns-windows-amd64.exe` |

## Verify

```bash
curl -fL -O \
  https://github.com/ersonw/mosdns-v4/releases/latest/download/SHA256SUMS.txt
sha256sum -c --ignore-missing SHA256SUMS.txt
```

On macOS use `shasum -a 256 -c --ignore-missing SHA256SUMS.txt`. The checksum
file lists every asset; `--ignore-missing` checks only the files you downloaded.

## Install

```bash
sudo install -m 755 /tmp/mosdns /usr/local/bin/mosdns
mosdns version
```

The binary is statically linked (`CGO_ENABLED=0`) and has no runtime library
dependency. Native install only; this fork is not packaged for Docker.

## Configuration

```bash
sudo mkdir -p /etc/mosdns
sudo curl -fL -o /etc/mosdns/config.yaml \
  https://raw.githubusercontent.com/ersonw/mosdns-v4/main/etc/mosdns/config.yaml
```

The example configuration contains the full annotated plugin set. Review these
before starting:

- `log.level`
- `servers[].exec`
- `data_providers` paths
- `fakeip_nat.ipv4_range` and `next_hop`
- `telegram_bot.token` and `chat_ids`

Optional helper scripts used by `telegram_bot` and ocserv:

```bash
sudo curl -fL -o /etc/mosdns/domain_manage.py \
  https://raw.githubusercontent.com/ersonw/mosdns-v4/main/etc/mosdns/domain_manage.py
sudo curl -fL -o /etc/mosdns/txt2dat.py \
  https://raw.githubusercontent.com/ersonw/mosdns-v4/main/etc/mosdns/txt2dat.py
sudo chmod +x /etc/mosdns/domain_manage.py /etc/mosdns/txt2dat.py
```

ocserv hook scripts:

```bash
sudo mkdir -p /etc/ocserv
sudo curl -fL -o /etc/ocserv/ocserv-updown.sh \
  https://raw.githubusercontent.com/ersonw/mosdns-v4/main/etc/ocserv/ocserv-updown.sh
sudo curl -fL -o /etc/ocserv/ocserv_notify.py \
  https://raw.githubusercontent.com/ersonw/mosdns-v4/main/etc/ocserv/ocserv_notify.py
sudo chmod +x /etc/ocserv/ocserv-updown.sh /etc/ocserv/ocserv_notify.py
```

On VyOS the hooks are copied to the op-mode directory and ocserv is restarted:

```bash
sudo install -m 755 /etc/ocserv/ocserv-updown.sh \
  /usr/libexec/vyos/op_mode/ocserv-updown-script.sh
sudo install -m 755 /etc/ocserv/ocserv_notify.py \
  /usr/libexec/vyos/op_mode/ocserv_notify.py
sudo systemctl restart ocserv
```

## Run

Foreground:

```bash
sudo mosdns start -c /etc/mosdns/config.yaml -d /etc/mosdns
```

Service (systemd, launchd and Windows service are supported by
`kardianos/service`):

```bash
sudo mosdns service install -c /etc/mosdns/config.yaml -d /etc/mosdns
sudo mosdns service start
sudo mosdns service status
```

`-d` changes the working directory before reading relative paths; `-c` is the
configuration file. Both are passed to the installed service.

Stop or remove:

```bash
sudo mosdns service stop
sudo mosdns service uninstall
```

## Privileges and platforms

- `fakeip_nat` with `use_tun: true` creates a TUN device and changes routes and
  nftables, so it needs root or administrator rights.
- Windows needs `wintun.dll` beside `mosdns.exe`.
- Linux is the only platform with `ip rule` / destination-mark routing and the
  full nftables data plane. macOS uses utun and a single routing table;
  FreeBSD and Windows use their native TUN implementations.
- A process supervisor is recommended. `telegram_bot` `/reload confirm` exits
  with a non-zero code and expects systemd, launchd or GoLand to restart it.

## Related

- [Usage](usage.md)
- [Build from source](build.md)
- [Licensing](licensing.md)
