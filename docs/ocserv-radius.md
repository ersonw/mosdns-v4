# ocserv and RADIUS: what a vhost actually carries

Findings from investigating "a second ocserv cannot find users on the same RADIUS".
Sources: ocserv master (`src/auth/radius.c`, `src/subconfig.c`) and this repo's
`plugin/executable/radius/`.

## Conclusion

**ocserv does not send the vhost name to RADIUS.** Nor does the user name carry a
vhost prefix or suffix.

Attributes always present in an Access-Request:

| Attribute | Value |
| --- | --- |
| User-Name (1) | the name as typed, unmodified |
| User-Password (2) / CHAP-Password (3) | the secret, PAP or CHAP |
| NAS-IP-Address (4) / NAS-IPv6-Address | the local address of this connection, `pctx->our_ip` |
| Calling-Station-Id | the client's public address |
| Acct-Session-Id (44) | session id, also sent at authentication time |
| Connect-Info | client user agent |
| Service-Type (6) / NAS-Port-Type | fixed Authenticate-Only / Async |
| NAS-Identifier (32) | sent **only** when `auth` configures `nas-identifier=` |

The `nas-identifier` value is a static string copied verbatim from the config;
ocserv does not substitute the vhost domain (`src/subconfig.c` assigns the value
straight to `additional->nas_identifier`).

## What a vhost really selects

A vhost selects **which configuration ocserv uses** - which `auth` line, which
`radiusclient.conf`, which server address, which certificate. It does not add a
tenant dimension inside one RADIUS user table.

Vhost selection is driven by the **SNI** of the client's TLS handshake, which must
equal the vhost `domain`. Connecting by IP sends no SNI and always lands on the
default context.

## Current plugin behaviour

`plugin/executable/radius/` keeps one global table keyed by the exact user name:

```sql
CREATE TABLE radius_users (name TEXT PRIMARY KEY, password, group_name, ip, ...)
```

`handleAccess` reads only User-Name and User-Password (or uses its presence to
reject CHAP) and writes Class back as the group. The constants
`attrNASIdentifier`, `attrNASIPAddress`, `attrNASPort` exist in `radius_packet.go`
but are never read.

So even with `nas-identifier` configured in ocserv, the plugin cannot tell sources
apart, and accounts stay global. Per-vhost isolation requires either a separate
RADIUS instance / `db_path` per vhost, or adding a vhost dimension to the account
table.

## A live case

Several nodes were cloned from one image, so they share hostname and machine-id
and look like a single machine. Identify them by their egress public address, not
by hostname.

Logs from the failing node:

```
sec-mod: using 'plain' authentication to authenticate user
error in plain authentication; cannot open: /run/ocserv/default/ocpasswd
```

The generated config shows the default context using
`auth = "plain[/run/ocserv/default/ocpasswd]"` while that file does not exist, and
radius configured only inside a `[vhost:...]` section. The request landed on
vhost 0 and never reached RADIUS.

Checklist:

1. `grep -nE "auth =|acct =|\[vhost" /run/ocserv/ocserv.conf` - the auth method per context;
2. `journalctl -u ocserv | grep -i "vhost"` - confirm the intended vhost loaded;
   after a domain/port edit, `no ipv4-network or ipv6-network options set` means it did not;
3. capture to prove a request was sent: `tcpdump -i any -n -vv udp port 1812`;
4. connect with the vhost `domain` (the certificate SAN must cover it), never by IP.

## References

- ocserv `src/auth/radius.c` - Access-Request construction
- ocserv `src/subconfig.c` - `nas-identifier=` parsing
- `docs/plugins/radius.md` in this repo - plugin arguments and account management
