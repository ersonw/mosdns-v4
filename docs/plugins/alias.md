# alias

[简体中文](alias.cn.md) | English

**Source:** `plugin/executable/alias/alias.go`, `store.go`, `alloc.go`,
`admin.go`, `egress.go`, `stack.go`, `gateway.go`, `tun_linux.go`,
`bind_linux.go`

## Overview

`alias` serves a domain list under a configurable suffix and carries the
traffic that follows its answer on its own tun device. It does not depend on
`data_provider` and it does not wrap or reuse `fakeip_nat`: the list belongs to
the plugin (`domain_file`), the virtual segment belongs to the plugin
(`ipv4_range`), and the outlet is decided when a packet arrives, not when the
query is answered.

- With `replace_suffix: true`, the last label is dropped first and
  `dot_replacement` then flattens the remaining dots before the suffix is
  appended (`ip138.com` → `ip138.local`, `www.ip138.com` → `www-ip138.local`).
- With `dot_replacement` set to anything other than `.`, the dot-free alias
  (`ip138-com.local`, `www-ip138-com.local`) is the only served form; the
  dotted form is not answered. A subdomain prefix that already contains the
  replacement string cannot be reversed unambiguously and is left to the
  normal chain. Entries that collapse to the same flat label are rejected at
  startup.
- A query for `<real>.<suffix>` (or `<stem>.<suffix>` with `replace_suffix`)
  that matches the list is answered immediately with an address from
  `ipv4_range`. No upstream lookup happens at query time.
- A packet to that virtual address enters the plugin's TUN. The virtual address
  maps back to the real name. With an active proxy the name is handed to the
  proxy unresolved; without one the name is resolved at that moment and dialled
  from `next_hop_dev` through `next_hop`.
- TCP port 80 is terminated by an HTTP gateway: plain HTTP in, rewritten `Host`
  out, HTTPS to the upstream when the entry says so.

## Arguments

| Key | Default | Meaning |
|---|---|---|
| `domain_file` | required | Owned list file, one `[scheme://]domain` per line; per-entry `https+insecure://` is supported. |
| `suffix` | `local` | Suffix of every served name; single or multi label. |
| `replace_suffix` | `false` | `false` appends (`ip138.com` → `ip138.com.local`); `true` drops the last label first, then applies `dot_replacement` to the rest and appends the suffix (`ip138.com` → `ip138.local`, `www.ip138.com` → `www-ip138.local`). |
| `alias_mode` | `readable` | `readable` keeps the real name in the alias; `opaque` encodes it as a reversible base32 label (`ip138.com` → `nfydcmzyfzrw63i.aa3.dev`) so Chrome does not treat `ip138-com.aa3.dev` as a lookalike of `ip138.com`. Cannot be combined with `replace_suffix`; names longer than one DNS label fall back to the readable flattened form. |
| `dot_replacement` | `.` | Separator substituted for every remaining dot after `replace_suffix` has handled the last label, before the suffix is added. `.` means unchanged; `-` flattens `ip138.com` to `ip138-com.dyize.com`, and with `replace_suffix: true` yields `ip138.dyize.com` / `www-ip138.dyize.com`. It must not contain a dot or whitespace; with `replace_suffix: true`, two entries that flatten to the same label are rejected at startup. |
| `ipv4_range` | required | Virtual IPv4 segment, at least a `/29`. |
| `ttl` | `60` | TTL of the virtual A answer. |
| `upstream_scheme` | `http` | Default scheme for entries without one: `http`, `https` or `auto`. |
| `add_forwarded_headers` | `false` | Add `X-Forwarded-Host`, `X-Forwarded-For` and `X-Forwarded-Proto: http`. |
| `redirect_to_alias` | `false` | Also answer the listed real names (same virtual address) and make a non-alias `Host` answer `302` to the alias host with the original path and query. Off by default: the list must not hijack names other plugins already serve. |
| `tls_cert_file` / `tls_key_file` | empty | Certificate pair used to terminate TLS on 443. With it, HTTPS enters the same gateway and redirects use `https://<alias>`; without it, 443 stays byte-transparent. Both must be set together. The certificate must cover every Host that reaches 443 through the virtual addresses. |
| `tun_dev` | empty | Empty auto-allocates `lga0..lga63`; a name reuses the device. |
| `tun_mtu` | auto | `0` auto: 1500 direct, 1400 with a proxy; range 576..1500. |
| `proxy` | empty | `socks5`, `socks5h`, `http` or `https`. |
| `proxy_insecure` | `false` | Skip certificate verification for an `https://` proxy. |
| `next_hop` | empty | Gateway for the direct outlet. |
| `next_hop_dev` | empty | Interface for the direct outlet; also used for socket binding. |
| `route_table` | `100` | Dedicated table for the direct outlet route and rule. |
| `rule_priority` | `1200` | Priority of the `ip rule` that selects that table. |
| `resolver` | empty | Plugin tag used to resolve names on the direct outlet. |

Linux only: `stack.go` uses a gVisor netstack and `tun_linux.go` creates the
device. Other platforms fail at startup with an explicit error.

## DNS behaviour

| Query | Answer |
|---|---|
| A for a served name | Virtual address from `ipv4_range`, `ttl` seconds. |
| A for a listed real name (`redirect_to_alias`) | Same virtual address as its alias form. Only an exact listed name matches; real subdomains are left to the normal path. |
| AAAA for a served name | Empty answer (`NOERROR`, no record). |
| Other qtype for a served name | Passed to the next plugin in the chain. |
| A for a name that is not served | Passed to the next plugin. |
| Address pool exhausted | `SERVFAIL`. |

The plugin is both a `MatcherPlugin` and an `ExecutablePlugin`, so it can be
used alone in a sequence or after a matcher.

## List file

One entry per line, `#` starts a comment (whole line or trailing), BOM and
CRLF are accepted. `scheme://` is optional and defaults to `upstream_scheme`.
`https+insecure://` is an explicit per-entry opt-in for legacy origins whose
certificate is expired or otherwise unverifiable: it still uses TLS, but skips
certificate and hostname verification for that domain only. Do not use it
unless the origin is trusted by another means; normal `https://` keeps full
verification. `auto://` tries HTTPS first and falls back to HTTP.
Only plain domains are accepted: `domain:`, `full:`, `keyword:`, `regexp:` and
`provider:` prefixes, wildcards, IP addresses and paths are rejected. Entries
are deduplicated; adding a name that already exists with another scheme
updates its scheme instead of creating a second line. A subdomain of a listed
name is served too, and matches the longest listed suffix.

Every mutation rewrites the file atomically (temporary file + `rename`), and
`reload` drops the mapping of names the file no longer serves. At startup and
after every `reload`, each listed name is preallocated a virtual address and its
rendered alias host is inserted into the runtime alias table; subdomains are
allocated on their first query. DNS answers and gateway redirects consult that
table first and only allocate when the name has no mapping yet.

## Data plane

1. The device is created or reused, MTU and address are applied, and the
   address gets a connected route for the whole segment.
2. TCP is terminated in the netstack. Port 80 goes to the HTTP gateway; every
   other port is forwarded byte-transparently to `domain:port`.
3. Proxy outlet: SOCKS5 (CONNECT by domain, so `socks5` and `socks5h` behave
   the same), HTTP CONNECT, or HTTPS proxy (TLS to the proxy first).
4. Direct outlet: the name is resolved at connect time through `resolver`
   (system resolver when unset), then dialled from the device address with
   `SO_BINDTODEVICE`. With `next_hop`/`next_hop_dev`, a dedicated table plus an
   `ip rule` on the source address pin that exit.
5. UDP is relayed on the direct outlet. With a proxy active, UDP is dropped on
   purpose: a TCP-only proxy cannot carry it, and sending it direct would leak
   the real address. The client falls back to TCP.
6. ICMP echo to a mapped virtual address is answered by the plugin itself: it
   swaps the addresses, flips the type to echo reply, recomputes the IPv4 and
   ICMP checksums and writes the packet back to the device. Nothing is sent to
   the real host, and other ICMP types are left to the stack (dropped). The
   kernel must have `net.ipv4.ip_forward=1`; the plugin warns at startup when
   it is off.

## HTTP gateway

With `redirect_to_alias`, only a request whose `Host` is a listed real name
(or a subdomain of one) is answered locally with `302 Found` and
`Location: <scheme>://<its alias host><path?query>`; the upstream is not
contacted. The alias host itself and a Host that is not in the list are not
redirected and follow the normal upstream path. A same-host upstream redirect
(typically `http://` to `https://` or a path canonicalisation) is followed
inside the gateway; the client receives the final response instead of the
alias host being redirected back to itself. Without `tls_cert_file`/`tls_key_file` only plain HTTP on
80 is redirected and 443 stays byte-transparent, so the real certificate keeps
validating. With the pair, 443 is terminated by the plugin, the request enters
the same gateway and the redirect scheme is `https`. The certificate must cover
both the real Host being redirected and the alias host it points at; a name
outside the certificate fails verification before any redirect is seen.

Before forwarding, `Host` is rewritten to the real name and the alias host in
`Origin` / `Referer` is rewritten to that real name too (the scheme follows the
actual upstream http/https). Other browser headers (`User-Agent`, `Accept`,
`Accept-Language`, `Cookie`, `Sec-Fetch-*`, `sec-ch-ua`, and others) pass
through unchanged; only hop-by-hop headers are removed. When the client
advertises compression, the gateway keeps only `gzip` / `deflate` it can decode
and never adds a coding the client did not offer.

On the response side, same-site URLs in `Location`, `Content-Location`,
`Refresh`, `Link`, and in `text/html` bodies (absolute and protocol-relative,
including subdomains) are rewritten to the corresponding alias name. External
site links are left untouched. HTML is rewritten only for status 200, bodies
up to 8 MiB, and decodable encodings; after rewriting the gateway drops
`Content-Encoding`, `ETag`, `Last-Modified`, `Content-MD5`, `Accept-Ranges`
and recomputes `Content-Length`.

A request with `Upgrade` and `Connection: upgrade` (WebSocket) is handled as a
tunnel: the handshake keeps `Connection`/`Upgrade` and the `Sec-WebSocket-*`
fields, a `101 Switching Protocols` response is relayed verbatim (including
`Sec-WebSocket-Accept`), and then bytes are copied in both directions until
either side closes. A refused upgrade is relayed as a normal response and the
connection closes.

The gateway reads HTTP/1.1 requests from the terminated flow, rewrites `Host`
and the request URI to the real domain, removes hop-by-hop headers, and sends
`Connection: close`. Response `Location` values that point at the real domain
are rewritten back to the alias name, and `Domain=` attributes on
`Set-Cookie` are dropped so the cookie stays inside the alias origin. A failed
upstream returns `502 Bad Gateway` in plain text.

`upstream_scheme: auto` tries TLS on 443 first and falls back to plain HTTP on
80.

## Bot commands

`/alias` discovers loaded alias plugins through `pkg/alias_admin.Admin`.

| Command | Permission |
|---|---|
| `/alias`, `/alias <tag>`, `/alias <tag> list` | `alias` |
| `/alias <tag> add [scheme://]d`, `del`, `mod`, `clear` | `alias` |
| `/alias <tag> reload` | `alias` |
| `/alias <tag> suffix <s>` | `config` |
| `/alias <tag> range <cidr>` | `config` |

`alias` is part of the plain administrator role; `config` is not. `suffix` is
applied at runtime and written back to the config file. `range` is validated by
the plugin, written to the config file, and needs a process restart: existing
device addresses, the allocator and the outlet rule all have to be rebuilt.

Every list mutation purges the state of the affected name: virtual address,
reverse mapping, cached resolution inside the plugin, and the answers other
plugins cached for that name.

## Limitations

- Without `tls_cert_file`/`tls_key_file`, the client must use plain HTTP for the
  gateway path. A client that upgrades to `https://<alias>` gets the certificate
  of the real domain and fails name verification unless a TLS terminator is in
  front. With the pair, the plugin itself terminates 443, but a Host outside
  the certificate still fails verification.
- UDP is not carried while a proxy is active; QUIC falls back to TCP.
- Only ICMP echo is answered. ICMP errors and traceroute probes are not
  synthesized, and IPv6 virtual addresses are not implemented.
- Mappings are in memory only; a restart preallocates the list again, and
  subdomains are allocated on their first query.
- The gateway handles port 80; HTTP on other ports is forwarded transparently
  without Host rewriting.
- `redirect_to_alias` only redirects HTTPS when `tls_cert_file`/`tls_key_file`
  are configured. The pair is global to the plugin, so do not enable it when
  the served list contains names outside that certificate.
- A TLS-terminated 443 is an HTTP gateway, not a transparent relay: non-HTTP
  TLS protocols on that virtual address do not pass through.
- Enabling `redirect_to_alias` makes every A query for the exact listed names
  return the virtual address, so do not overlap that file with names other
  plugins (fakeip, providers) already serve.
- Only same-host HTTP(S) redirects are followed internally. A redirect to a
  different host (for example a site WAF redirecting to `127.0.0.1`) is passed
  through unchanged; that is upstream behaviour, not an alias loop.
