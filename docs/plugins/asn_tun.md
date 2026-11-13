# asn_tun

[简体中文](asn_tun.cn.md) | English

**Source:** `plugin/executable/asn_tun/*.go`

## Overview

`asn_tun` routes traffic destined for the prefixes announced by a configured
list of ASNs into a userspace TUN stack. It does **not** allocate fake IPs and
**does not** rewrite DNS answers: clients receive the real destination address.
The TUN device sees the real destination, terminates TCP/UDP in a gVisor
netstack, and re-dials the flow through either the configured proxy or the
local direct outlet.

This is the real-destination counterpart of `fakeip_nat`'s TUN data path. It
reuses the proven proxy outlet implementation from `fakeip_nat`, but owns its
prefix set, mark rules and TUN routing.

## Data path

```text
ASN list
  -> IPv4 prefix list (ipverse)
  -> nftables interval set
  -> destination filter (skip_ip matches stop here; unmatched continue)
  -> nft mark on prerouting (all interfaces, or only mirror_dev when set)
  -> nft mark on output (global mode only)
  -> ip rule fwmark <mark> lookup <route_table>
  -> default dev <tun_dev>
  -> gVisor TCP/UDP stack
  -> proxy (real target IP) or direct outlet (real target IP)
```

The cached prefix set is loaded synchronously at startup and written to nft, so
the first packet after a restart is still marked. A background thread then
fetches all ASNs, runs `cidr_merge.py`, and replaces the nft set only when the
result changes. With no cache, the plugin starts with an empty set and begins
marking after the first async refresh completes.

## Arguments

| Key | Default | Meaning |
|---|---|---|
| `asn` | required | ASN numbers to load, for example `[4134, 4837]`. |
| `source` | `ipverse` | Prefix provider. `ipverse` fetches from GitHub; `bgpq3` runs local `fetch_script` and `merge_script`. |
| `refresh` | `12h` | Periodic refresh interval; `0` disables the ticker, but one async refresh still runs at startup. |
| `cache` | `/config/mosdns/asn_tun_prefixes.json` | Last successfully merged prefix list. It is loaded synchronously at startup to build the nft set; failed async refreshes keep using it. |
| `fetch_script` | `<config dir>/scripts/bgpq3_fetch_asn.py` | ASN prefix fetch script used when `source: bgpq3`; downloaded automatically when missing. |
| `merge_script` | `<config dir>/scripts/cidr_merge.py` | CIDR merge script run after all ASNs are fetched; downloaded automatically when missing. |
| `python` | `python3` | Interpreter used for the scripts. |

Relative paths are resolved against the directory of the config file. A missing
script is downloaded from
`https://raw.githubusercontent.com/ersonw/mosdns-v4/refs/heads/main/etc/mosdns/scripts/`
into `<config dir>/scripts/`. They do not need an executable bit because the
plugin runs them through the configured `python` interpreter.
| `tun_dev` | `asn0` | TUN device name, at most 15 characters. |
| `tun_addr` | `192.0.2.1/32` | Device-local IPv4 address. It is not a client-facing virtual IP and is never returned by DNS. |
| `tun_mtu` | `0` | `0`: 1500 direct, 1400 proxy. Range 576..1500. |
| `mirror_dev` | empty | Ingress interface carrying mirrored/SPAN traffic. When set, the prerouting rule is limited with `iifname` and the local output mark chain is not installed; empty = global mode over all interfaces and local output. |
| `skip_ip` | empty | Destination-address skip list. Accepts the same forms as `response_matcher`'s `ip` field: CIDRs, `provider:<tag>`, and `provider:<tag>:<category>`. Matched destinations never get the ASN mark; only unmatched destinations enter the ASN/TUN path. |
| `nft_table` | `asn_tun` | nftables table name; letters, digits and `_` only. |
| `mark` | `123` | fwmark for marked destinations. |
| `route_table` | `123` | Dedicated table with `default dev <tun_dev>`. Must not be `main`. |
| `route_rule_priority` | `1000` | Priority of the ingress `ip rule`; range 1..32765. |
| `next_hop` | empty | Gateway for the direct outlet. |
| `next_hop_dev` | empty | Interface for the direct outlet and `SO_BINDTODEVICE`. |
| `egress_mark` | `mark + 1` | fwmark for the plugin's own direct sockets. |
| `egress_table` | `124` | Route table for the direct sockets; `default via next_hop dev next_hop_dev`. |
| `proxy` | empty | `socks5`, `socks5h`, `http`, `https`, `trojan` or `gost`, same syntax as `fakeip_nat`. |
| `proxy_insecure` | `false` | Skip TLS verification for self-signed `https` / `trojan`. |

Without `proxy`, `next_hop` or `next_hop_dev` must be set: the plugin has to
know where its own direct sockets leave. A configured proxy is probed at
startup; a failed probe aborts startup instead of silently switching to direct.

## Requirements

- Linux, root or `CAP_NET_ADMIN` (TUN, nftables and policy routing).
- `nft`, `ip`, `sysctl`.
- IPv4 only in this version. IPv6 prefixes are not installed; adding IPv6
  requires a separate `ipv6` protocol in the netstack and `ip -6` rules.

## Important behavior

- `tun_addr` is a device endpoint only. It does not appear in DNS, and no
  fake-IP mapping table exists.
- `mirror_dev` is for a switch mirror/SPAN feed. When set, only packets entering
  that interface are matched and the local output chain is omitted; empty means
  global mode over every interface and local output. It does not copy packets:
  it diverts the mirrored copies received on that interface into the TUN, so
  the interface must be a dedicated mirror port, not a production ingress.
- `skip_ip` filters destinations at the nft layer: matched packets are not
  marked and never enter the TUN; unmatched packets continue through the ASN
  path. Unlike the internal `bypass` set, which only protects the proxy
  server/`next_hop`, this is a user-configurable business skip list.
- The proxy server and `next_hop` addresses are added to the nft `bypass4`
  set. Traffic to them is not marked, so a proxy endpoint inside a selected
  ASN cannot be routed back into the TUN.
- Marked packets never use `next_hop` directly. They must enter the TUN;
  `next_hop` belongs to the plugin's direct egress sockets, selected by
  `egress_mark` and `egress_table`.
- Only packets with fwmark 0 are marked. If another policy already marked the
  packet, this plugin leaves that mark alone. On a router with its own
  destination marks, adjust `route_rule_priority` or disable that competing
  path.
- ICMP is not handled by the netstack. Marked ICMP will not be proxied or
  relayed in this version.
- UDP over `http` / `trojan` is not available in the underlying outlets. Such
  UDP flows are logged and dropped; `socks5` can carry UDP.

## Example

```yaml
plugins:
  - tag: asn_tun
    type: asn_tun
    args:
      asn: [4134, 4837]
      source: bgpq3
      refresh: 12h
      cache: /config/mosdns/asn_tun_prefixes.json
      fetch_script: scripts/bgpq3_fetch_asn.py
      merge_script: scripts/cidr_merge.py
      python: python3

      tun_dev: asn0
      tun_addr: 192.0.2.1/32
      tun_mtu: 1400
      mirror_dev: ""             # e.g. eth1; empty = global
      skip_ip:                   # destination CIDRs/providers excluded from ASN marking
        - "provider:geoip:cn"

      nft_table: asn_tun
      mark: 123
      route_table: 123
      route_rule_priority: 1000

      next_hop: 10.0.0.1
      next_hop_dev: eth0
      egress_mark: 124
      egress_table: 124

      # proxy: socks5://user:pass@10.0.0.2:1080
```

The plugin is a standalone data-plane plugin. It can be listed under
`plugins` without being added to a DNS `sequence`; if it is placed in a
sequence, its `Exec` simply passes the query through.
