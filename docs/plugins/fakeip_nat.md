# fakeip_nat

[简体中文](fakeip_nat.cn.md) | English

**Source:** `plugin/executable/fakeip_nat/fakeip_nat.go`, `nat.go`, `tun.go`,
`tunstack.go`, `tun_icmp.go`, `egress.go`, `tun_egress.go`, `route_ledger.go`,
`mapping_runtime.go`, `traffic_watch.go`, `traffic_capture.go`

## Overview

`fakeip_nat` assigns a fake IPv4 address to each A-record domain, rewrites the
answer, and then carries traffic either through the built-in nftables NAT
(default) or through a userspace TUN stack (`use_tun: true`).

The data plane and the mapping database are separate:

- The mapping database stores domain ↔ fake IP and the most recent real IPs.
- The NAT plane uses nftables DNAT plus host routes.
- The TUN plane terminates TCP/UDP in a gVisor netstack and dials the real
  destination or the configured proxy.

The old `script` callback has been removed. A legacy `script` key is ignored
with a warning.

## Arguments

| Key | Default | Meaning |
|---|---|---|
| `db_path` | `/config/mosdns/fakeip.db` | SQLite mapping and access database. |
| `table_prefix` | `default` | Prefix for nft table names; letters, digits and `_` only. |
| `ipv4_range` | `198.18.0.0/15` | Fake IPv4 range; must contain at least two usable addresses. |
| `ttl` | `60` | Fake-IP mapping TTL in the DNS answer. |
| `next_hop` | empty | Gateway for the direct egress path. |
| `next_hop_dev` | empty | Egress interface; also used for socket binding. |
| `route_table` | `main` | Host-route table. A non-`main` table is Linux-only; macOS/Windows fall back to `main`. |
| `route_aggregation` | `true` | Every 30s, collapse managed `/32` host routes into CIDRs. |
| `route_mark` | `0` | `0` disables mark routing. Non-zero marks destination real IPs for policy routing; Linux only. |
| `route_rule_priority` | `1000` | Priority of the `ip rule` used by mark routing. |
| `realip` | `false` | Do not allocate fake IPs or DNAT; route by real destination IP. Useful with `route_mark` and TUN. |
| `mss_clamp` | `0` | `0` disables; set `1360` for a 1400-byte tunnel MTU to rewrite SYN/SYN-ACK MSS. |
| `use_tun` | `false` | Enable the TUN data plane. |
| `tun_dev` | empty | Empty auto-allocates; a name reuses an existing device. |
| `tun_mtu` | `0` | `0` auto: 1500 direct, 1400 proxy; an explicit value wins. |
| `tun_route_table` | `100` | Dedicated table for the TUN direct egress on Linux. |
| `proxy` | empty | `socks5`, `socks5h`, `http`, `https`, `trojan` or `gost`. |
| `proxy_insecure` | `false` | Skip TLS verification for self-signed `https` / `trojan`. |
| `hop_name_suffix` | `table_prefix` | Single-label suffix used in traceroute PTR names. Invalid values fail startup. |
| `record_ttl` | `168h` | Mapping retention. Empty = 7 days; `"0"` disables cleanup. |
| `access_log` | `true` | Record `(client_ip, domain)` per fake-IP answer. |
| `access_ttl` | `168h` | Access-record retention; `"0"` disables cleanup. |
| `timezone` | `Asia/Shanghai` | Display timezone for admin output; the DB always stores Unix seconds. |

`table_prefix` and `ipv4_range` are validated at startup. `next_hop` must be a
valid IP. `proxy` is only used by the TUN plane; with `use_tun: false` it logs a
warning and is not probed.

## NAT data plane (`use_tun: false`)

1. Create the `fakeip_<prefix>` nftables table with `dnat_map` and
   `prerouting` / `forward` / `postrouting` chains.
2. Check the existing mapping. If it still works, reuse it.
3. Otherwise probe candidates: the configured real IP plus the last 15 real IPs
   from SQLite, testing TCP 443/80 and ICMP echo.
4. Write the selected real IP into `dnat_map`, add a `/32` host route, and
   record the route in the route ledger.
5. Periodically aggregate managed `/32` routes into strict CIDRs.

`postrouting` masquerades only `ct status dnat`, so it does not SNAT unrelated
traffic on the same interface. All `nft`/`ip` commands are serialized. If table
creation fails, the task is skipped without leaving half-written host routes.
`cleanupDataPath` removes ledger routes first, then scans for routes that still
cover known real IPs; it will not delete routes that the ledger cannot prove it
owns. A table whose shape no longer matches the configuration is recreated.

## Destination-mark routing (`route_mark`)

When `route_mark` is non-zero, real IPs move from host routes into the nft set
`real_ipv4` (`type ipv4_addr; flags timeout; timeout 1h`). Two chains mark
packets:

- `mark_prerouting` at prerouting priority 0, after DNAT(-100), so the
  destination is already the real IP in fake-IP mode.
- `mark_output` with `type route hook output`, so locally generated traffic
  reruns route selection after the mark changes.

Both use `ip daddr @real_ipv4 ip saddr != <ipv4_range> meta mark set <route_mark>`.
A dedicated route table gets `default via <next_hop> dev <next_hop_dev>`, and an
`ip rule fwmark <mark> lookup <table>` routes marked packets. On TUN with
`realip`, the default route points at the TUN device instead.

This mode requires Linux and a `route_table` other than `main`. In TUN +
fake-IP mode the mark path is disabled; in TUN + `realip` it remains active.

## TUN data plane (`use_tun: true`)

The plugin creates a TUN device, assigns the first address of `ipv4_range` with
the same prefix length, and lets the kernel create the connected route for the
whole range. The first address is reserved and is never allocated to a domain;
allocation starts at the second address.

Platforms:

| Platform | Device | Notes |
|---|---|---|
| Linux | `/dev/net/tun` (`mth0`, `mth1`, …) | `ip tuntap/link/addr/route`; IPv6 disabled best-effort. |
| macOS | utun | Kernel assigns the unit; an existing `utunN` owned by another process is rejected. |
| FreeBSD | `/dev/tun<N>` | `TUNSIFHEAD` / `TUNSIFMODE`. |
| Windows | Wintun | Requires `wintun.dll` and administrator rights. |

Creating a device needs root/administrator privileges on every platform. If
device creation fails, the plugin logs a warning and startup continues.

A gVisor netstack terminates TCP and UDP. With a working proxy, TCP is dialed
as `domain:port` and the proxy resolves the name. Without a proxy, the plugin
looks up the most recent real IP for the domain and dials it directly.

DNS answers prefer IPv4 globally: AAAA queries get an empty answer, and A
queries with an A record get a fake IPv4. An IPv6-only name (no A record, only
AAAA) can still be reached through a fake IPv4 in two cases:

- **Proxied outlet** (`use_tun: true` with a working `proxy`): the plugin
  returns a synthesized A answer and dials the *domain*, leaving IPv6 resolution
  to the proxy.
- **Direct tun outlet** (`use_tun: true`, no proxy or an unusable proxy): the
  plugin probes the host's own IPv6 egress first (`ipv6_egress`, below). When
  the probe succeeds it returns the synthesized A answer and records the probed
  **AAAA addresses** in the real-IP table, so the userspace stack can dial them.
  When the probe fails the old behaviour is kept exactly: empty A answer, no
  allocation, nothing recorded.

The direct path requires a working IPv6 uplink on the box itself (native IPv6,
NAT66 or NPTv6 all qualify). Without one the probe keeps failing and no fake A
is handed out — a client that received one could only time out.

```yaml
  - tag: fakeip_tun
    type: fakeip_nat
    args:
      use_tun: true
      proxy: "socks5h://user:pass@10.0.0.9:1080"
      proxy_insecure: false
      next_hop: "192.168.1.1"
      next_hop_dev: "en0"
      tun_route_table: 100
      # Direct-outlet IPv6 detection: a fake IPv4 for an IPv6-only name is
      # only handed out while this probe succeeds.
      ipv6_egress: auto                 # auto (default, probe) | off (never allocate)
      ipv6_probe: "[2606:4700:4700::1111]:443"   # address literal, so the probe never needs DNS
      ipv6_probe_interval: "5m"         # re-check period; "0" probes once at startup
```

### Direct egress and SNAT

Without a proxy, Linux installs a dedicated route table
(`tun_route_table`, default `100`):

```text
ip route replace default via <next_hop> dev <next_hop_dev> table <table>
ip rule add from <ipv4_range> to !<ipv4_range> lookup <table>
```

The `to !<range>` exclusion is required: packets sent by the client to a fake
IP also have a source address inside the range. Without the exclusion they
would be pulled out of the TUN and sent directly on the physical interface.

Linux also installs an independent nft table `<prefix>_tun_snat`:

```text
oifname <next_hop_dev> ip saddr <ipv4_range> masquerade
```

This rewrites the source to the host address before the packet leaves the
physical interface. Routing happens before SNAT. The table is separate from
the NAT data plane's DNAT table.

macOS has one routing table and no `ip rule`; it only binds the source address
and interface, and `next_hop` has no effect there. When `next_hop` and
`next_hop_dev` are both empty, no table, source binding or SNAT is installed.

### Proxy egress

Supported schemes:

- `socks5://` and `socks5h://`: RFC 1928 CONNECT, RFC 1929 auth, UDP ASSOCIATE.
- `http://` and `https://`: CONNECT only; UDP falls back to direct.
- `trojan://`: TLS with `sha256(password)[:56]`, plus its UDP associate frames.
- `gost://user:pass@host:1080`: probes socks5h, socks5, trojan, https and http,
  keeps the protocols that complete a handshake, and chooses the fastest TCP
  and UDP protocol. For TCP, ports 80/443 keep the fastest protocol; every
  other port prefers socks5h/socks5 first and only falls back to
  trojan/https/http, so an SSH flow is not carried by gost's HTTP listener.

`socks5://` normally resolves locally, but the local resolver is often this
plugin, so it can answer with a fake IP. The plugin detects that and keeps the
domain for the proxy, equivalent to `socks5h://`.

If the proxy probe fails, the plugin logs a warning and falls back to direct
egress. An unsupported scheme fails startup.

## ICMP and traceroute

- Echo requests to a fake IP are answered locally when a proxy is configured,
  preserving the client ID, sequence and payload. Proxy protocols do not
  carry ICMP, so forwarding would only time out.
- Without a proxy, echo requests are sent to the real IP through a raw socket
  bound to `next_hop_dev` when the platform supports it.
- UDP probes with TTL 2..30 are re-probed to the real IP. The reply uses a
  virtual in-range source address derived from the real hop, so the reply
  always routes back into the TUN.
- The PTR for a virtual hop address returns
  `<real_ip>.<hop_name_suffix>.`, which makes `traceroute` show
  `192.168.10.1.mosdns (198.19.x.y)`.
- The first hop uses a substitute in-range address; using the device address
  directly would be dropped as a martian source by the receiving host.
- ICMP errors quote the client's actual IP header plus 8 transport bytes; a
  shorter quote is rejected by macOS/XNU as `bad length`.

## Mapping, retention and access records

The runtime map is loaded from `<prefix>_mapping` at startup. Pending rows are
skipped until first allocation. In NAT mode the map is reconciled with the nft
`dnat_map`: missing firewall entries are restored from the latest real IP, and
unknown firewall addresses are reserved so they cannot be allocated twice.

Allocation scans from offset 2 upward, skipping reserved addresses, in-use
addresses and recently used traceroute hop addresses. It writes a `pending`
row first, then flips it atomically; a unique conflict advances to the next
candidate.

`record_ttl` retention runs 5 seconds after startup and then every
`min(record_ttl, 1h)`, with a 1-minute floor. It compares the maximum of the
in-memory touch, the DB `last_seen` and `created_at` with the cutoff. It drops
both the domain/fake-IP row and the matching `real_ip` rows, and the same TTL
expires the traffic-watch domain cache. Pending rows never expire. The address
is returned to the pool only after the delete transaction commits.

With `access_log`, every fake-IP answer inserts `(client_ip, domain)` into
`<prefix>_access` with `fake_ip`, `first_seen`, `last_seen` and `hits`. Real IPs
are not duplicated; readers take the latest real IP for the domain. Writes are
on the answer path but failures only log. `telegram_bot` `/access` exports the
records as XLSX.

## Logging and platforms

Logging uses the plugin logger and is split into Debug (per packet, per nft
command, per connection), Info (lifecycle and data-plane readiness), Warn
(degraded but usable paths) and Error (no usable data plane or inconsistent
state). Set `log.level: debug` only while troubleshooting.

Supported release targets: darwin amd64/arm64, linux amd64/arm/arm64/ppc64le,
freebsd amd64, windows amd64. MIPS targets are not built because
`modernc.org/libc` does not support them.

## Examples

Default NAT:

```yaml
- tag: fakeip_oversea
  type: fakeip_nat
  args:
    table_prefix: "oversea"
    ipv4_range: "198.18.0.0/16"
    hop_name_suffix: "oversea"
    next_hop: "10.131.160.3"
    next_hop_dev: "eth0"
    route_table: "main"
    route_aggregation: true
    route_mark: 0
    mss_clamp: 0
```

TUN with a proxy:

```yaml
- tag: fakeip_tun
  type: fakeip_nat
  args:
    table_prefix: "tun"
    ipv4_range: "198.19.0.0/16"
    use_tun: true
    tun_dev: ""
    tun_mtu: 0
    proxy: "socks5h://user:pass@10.0.0.9:1080"
    proxy_insecure: false
    next_hop: "192.168.1.1"
    next_hop_dev: "en0"
    tun_route_table: 100
    record_ttl: "168h"
    access_log: true
    access_ttl: "168h"
    timezone: Asia/Shanghai
```
