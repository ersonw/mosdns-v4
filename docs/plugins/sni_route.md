# sni_route

[简体中文](sni_route.cn.md) | English

**Source:** `plugin/executable/sni_route/`

## Overview

`sni_route` intercepts TCP connections entering one interface, reads the
`server_name` from the TLS ClientHello, and selects an exit by domain suffix. It
exists for clients that never ask this box's resolver: an app with its own
HTTPDNS, or a device whose encrypted-DNS tunnel returns real addresses to it.
Fake IP has nothing to intercept there, but the first TLS packet still carries
the name in clear text.

Data path:

```text
nftables prerouting (iifname + optional source + optional destination bypass)
  -> meta mark
  -> ip rule fwmark -> route table -> tun_dev
  -> gVisor TCP stack terminates the connection
  -> read ClientHello, parse SNI
  -> matched -> egress
  -> unmatched -> no exit selection; the flow goes back to the system route
  -> write the already-read bytes to the remote, then relay both directions
```

TCP only. QUIC carries its SNI encrypted; `block_quic` drops UDP/443 for the
captured clients so applications fall back to TCP. Off by default.

## Configuration

```yaml
- tag: sni_tiktok
  type: sni_route
  args:
    interface: eth1
    source:
      - 192.168.10.22/32        # one phone; omitted means 0.0.0.0/0
    domain:
      - match_tiktok_site       # borrow an existing query_matcher; list is OR
    block_quic: true
    egress: egress_sg           # matched flows use this egress_route outlet
    bypass_ip:
      - provider:geoip:cn       # keep domestic destinations on their direct path
```

`domain` holds `query_matcher` plugin tags, not suffixes. The matcher owns the
suffix/provider list, so the resolver and the SNI path share one domain table.
The matcher must be declared before `sni_route`. `domain_file` remains an
optional plain suffix file and is matched alongside the tags.

this one. A proxy outlet is given `domain:port` and resolves it on the far side;
a direct outlet is given the real destination address, because handing a name to
this box's resolver would produce a fake IP.

Private ranges, the TUN address, `198.16.0.0/15` and `198.18.0.0/15` are always
bypassed. `bypass_ip` accepts the same forms as `response_matcher`'s `ip` field,
including `provider:<tag>:<category>`.

## Parameters

| Name | Default | Description |
|---|---|---|
| `interface` | `eth0` | Ingress interface to intercept. |
| `source` | `0.0.0.0/0` | Client address/CIDR; omitted means all clients on the interface. |
| `ports` | `[443]` | TCP ports to intercept. |
| `domain` | empty | `query_matcher` plugin tags, ORed; suffix syntax belongs to the matcher. |
| `domain_file` | empty | One suffix per line, reloaded when the file changes. |
| `block_quic` | `false` | Drop UDP/443 for the captured clients. |
| `egress` | empty | Outlet tag for matched flows. |
| `tun_dev` | `sn0` | TUN device name. |
| `tun_addr` | `192.0.2.2/32` | TUN address, IPv4 /32. |
| `tun_mtu` | `1400` | TUN MTU. |
| `nft_table` | `sni_route` | nft table name. |
| `mark` | `130` | Intercept mark; must not collide with an existing one. |
| `route_table` | `130` | Dedicated routing table. |
| `route_rule_priority` | `1100` | `ip rule` priority. |
| `bypass` | empty | Extra destination prefixes to exclude. |
| `bypass_ip` | empty | Extra destination prefixes, providers allowed. |

## Notes

- Linux only; TUN, nft and `ip rule` need root.
- A failed data-plane start disables the plugin but keeps the DNS service up;
  configuration errors still fail at init.
- One instance owns one `nft_table`/`mark`/`route_table`/`tun_dev`; multiple
  instances need distinct values.
- Matching is SNI only. ECH or a handshake without SNI is relayed untouched.
