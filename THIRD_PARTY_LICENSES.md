# Third-Party Licenses

`mosdns-v4` is distributed under GPL-3.0-or-later. Release binaries include the Go modules below. Each module remains under its own license; the bundled text under `third_party/licenses/<module>@<version>/` controls.

This inventory covers runtime modules used by the release targets (linux/amd64, linux/arm64, darwin/amd64, darwin/arm64, windows/amd64, freebsd/amd64). Test-only modules are not listed.

| Module | Version | License | Notes |
|---|---|---|---|
| [github.com/AdguardTeam/dnsproxy](third_party/licenses/github.com_AdguardTeam_dnsproxy@v0.50.2/) | `v0.50.2` | Apache-2.0 |  |
| [github.com/AdguardTeam/golibs](third_party/licenses/github.com_AdguardTeam_golibs@v0.13.3/) | `v0.13.3` | Unlicense |  |
| [github.com/aead/chacha20](third_party/licenses/github.com_aead_chacha20@v0.0.0-20180709150244-8b13a72661da/) | `v0.0.0-20180709150244-8b13a72661da` | MIT |  |
| [github.com/aead/poly1305](third_party/licenses/github.com_aead_poly1305@v0.0.0-20180717145839-3fee0db0b635/) | `v0.0.0-20180717145839-3fee0db0b635` | MIT |  |
| [github.com/ameshkov/dnscrypt/v2](third_party/licenses/github.com_ameshkov_dnscrypt_v2@v2.2.7/) | `v2.2.7` | Unlicense |  |
| [github.com/ameshkov/dnsstamps](third_party/licenses/github.com_ameshkov_dnsstamps@v1.0.3/) | `v1.0.3` | Unlicense |  |
| [github.com/beorn7/perks](third_party/licenses/github.com_beorn7_perks@v1.0.1/) | `v1.0.1` | MIT |  |
| [github.com/cespare/xxhash/v2](third_party/licenses/github.com_cespare_xxhash_v2@v2.2.0/) | `v2.2.0` | MIT |  |
| [github.com/dgryski/go-rendezvous](third_party/licenses/github.com_dgryski_go-rendezvous@v0.0.0-20200823014737-9f7001d12a5f/) | `v0.0.0-20200823014737-9f7001d12a5f` | MIT |  |
| [github.com/dustin/go-humanize](third_party/licenses/github.com_dustin_go-humanize@v1.0.1/) | `v1.0.1` | MIT |  |
| [github.com/fsnotify/fsnotify](third_party/licenses/github.com_fsnotify_fsnotify@v1.6.0/) | `v1.6.0` | BSD-3-Clause |  |
| [github.com/go-telegram/bot](third_party/licenses/github.com_go-telegram_bot@v1.28.0/) | `v1.28.0` | MIT |  |
| [github.com/golang/protobuf](third_party/licenses/github.com_golang_protobuf@v1.5.3/) | `v1.5.3` | BSD-3-Clause |  |
| [github.com/golang/snappy](third_party/licenses/github.com_golang_snappy@v0.0.4/) | `v0.0.4` | BSD-3-Clause |  |
| [github.com/google/btree](third_party/licenses/github.com_google_btree@v1.1.3/) | `v1.1.3` | Apache-2.0 |  |
| [github.com/google/nftables](third_party/licenses/github.com_google_nftables@v0.1.0/) | `v0.1.0` | Apache-2.0 |  |
| [github.com/google/uuid](third_party/licenses/github.com_google_uuid@v1.3.0/) | `v1.3.0` | BSD-3-Clause |  |
| [github.com/hashicorp/hcl](third_party/licenses/github.com_hashicorp_hcl@v1.0.0/) | `v1.0.0` | MPL-2.0 |  |
| [github.com/inconshreveable/mousetrap](third_party/licenses/github.com_inconshreveable_mousetrap@v1.1.0/) | `v1.1.0` | Apache-2.0 |  |
| [github.com/josharian/native](third_party/licenses/github.com_josharian_native@v1.1.0/) | `v1.1.0` | MIT |  |
| [github.com/kardianos/service](third_party/licenses/github.com_kardianos_service@v1.2.2/) | `v1.2.2` | Zlib |  |
| [github.com/Knetic/govaluate](third_party/licenses/github.com_Knetic_govaluate@v3.0.0_incompatible/) | `v3.0.0+incompatible` | MIT |  |
| [github.com/magiconair/properties](third_party/licenses/github.com_magiconair_properties@v1.8.7/) | `v1.8.7` | BSD-2-Clause |  |
| [github.com/mattn/go-isatty](third_party/licenses/github.com_mattn_go-isatty@v0.0.16/) | `v0.0.16` | MIT |  |
| [github.com/matttproud/golang_protobuf_extensions](third_party/licenses/github.com_matttproud_golang_protobuf_extensions@v1.0.4/) | `v1.0.4` | Apache-2.0 | Apache-2.0 NOTICE included. |
| [github.com/mdlayher/netlink](third_party/licenses/github.com_mdlayher_netlink@v1.7.2/) | `v1.7.2` | MIT |  |
| [github.com/mdlayher/socket](third_party/licenses/github.com_mdlayher_socket@v0.4.1/) | `v0.4.1` | MIT |  |
| [github.com/metacubex/gvisor](third_party/licenses/github.com_metacubex_gvisor@v0.0.0-20260922041103-e2cbcd6e7400/) | `v0.0.0-20260922041103-e2cbcd6e7400` | Apache-2.0 |  |
| [github.com/miekg/dns](third_party/licenses/github.com_miekg_dns@v1.1.54/) | `v1.1.54` | BSD-3-Clause |  |
| [github.com/mitchellh/mapstructure](third_party/licenses/github.com_mitchellh_mapstructure@v1.5.0/) | `v1.5.0` | MIT |  |
| [github.com/nadoo/ipset](third_party/licenses/github.com_nadoo_ipset@v0.5.0/) | `v0.5.0` | GPL-3.0 | Replaced in `go.mod` by `github.com/IrineSistiana/ipset v0.5.1-0.20220703061533-6e0fc3b04c0a`. Actual source: `github.com/IrineSistiana/ipset v0.5.1-0.20220703061533-6e0fc3b04c0a`. |
| [github.com/pelletier/go-toml/v2](third_party/licenses/github.com_pelletier_go-toml_v2@v2.0.8/) | `v2.0.8` | MIT |  |
| [github.com/pires/go-proxyproto](third_party/licenses/github.com_pires_go-proxyproto@v0.7.0/) | `v0.7.0` | Apache-2.0 |  |
| [github.com/prometheus/client_golang](third_party/licenses/github.com_prometheus_client_golang@v1.16.0/) | `v1.16.0` | Apache-2.0 | Apache-2.0 NOTICE included. |
| [github.com/prometheus/client_model](third_party/licenses/github.com_prometheus_client_model@v0.4.0/) | `v0.4.0` | Apache-2.0 | Apache-2.0 NOTICE included. |
| [github.com/prometheus/common](third_party/licenses/github.com_prometheus_common@v0.44.0/) | `v0.44.0` | Apache-2.0 | Apache-2.0 NOTICE included; `goautoneg` is BSD-3-Clause. |
| [github.com/prometheus/procfs](third_party/licenses/github.com_prometheus_procfs@v0.11.0/) | `v0.11.0` | Apache-2.0 | Apache-2.0 NOTICE included. |
| [github.com/quic-go/qpack](third_party/licenses/github.com_quic-go_qpack@v0.4.0/) | `v0.4.0` | MIT |  |
| [github.com/quic-go/qtls-go1-20](third_party/licenses/github.com_quic-go_qtls-go1-20@v0.2.2/) | `v0.2.2` | BSD-3-Clause |  |
| [github.com/quic-go/quic-go](third_party/licenses/github.com_quic-go_quic-go@v0.35.1/) | `v0.35.1` | MIT |  |
| [github.com/redis/go-redis/v9](third_party/licenses/github.com_redis_go-redis_v9@v9.0.5/) | `v9.0.5` | BSD-2-Clause |  |
| [github.com/remyoudompheng/bigfft](third_party/licenses/github.com_remyoudompheng_bigfft@v0.0.0-20230129092748-24d4a6f8daec/) | `v0.0.0-20230129092748-24d4a6f8daec` | BSD-3-Clause |  |
| [github.com/spf13/afero](third_party/licenses/github.com_spf13_afero@v1.9.5/) | `v1.9.5` | Apache-2.0 |  |
| [github.com/spf13/cast](third_party/licenses/github.com_spf13_cast@v1.5.1/) | `v1.5.1` | MIT |  |
| [github.com/spf13/cobra](third_party/licenses/github.com_spf13_cobra@v1.7.0/) | `v1.7.0` | Apache-2.0 |  |
| [github.com/spf13/jwalterweatherman](third_party/licenses/github.com_spf13_jwalterweatherman@v1.1.0/) | `v1.1.0` | MIT |  |
| [github.com/spf13/pflag](third_party/licenses/github.com_spf13_pflag@v1.0.5/) | `v1.0.5` | BSD-3-Clause |  |
| [github.com/spf13/viper](third_party/licenses/github.com_spf13_viper@v1.16.0/) | `v1.16.0` | MIT |  |
| [github.com/subosito/gotenv](third_party/licenses/github.com_subosito_gotenv@v1.4.2/) | `v1.4.2` | MIT |  |
| [go.uber.org/atomic](third_party/licenses/go.uber.org_atomic@v1.11.0/) | `v1.11.0` | MIT |  |
| [go.uber.org/multierr](third_party/licenses/go.uber.org_multierr@v1.11.0/) | `v1.11.0` | MIT |  |
| [go.uber.org/zap](third_party/licenses/go.uber.org_zap@v1.24.0/) | `v1.24.0` | MIT |  |
| [golang.org/x/crypto](third_party/licenses/golang.org_x_crypto@v0.10.0/) | `v0.10.0` | BSD-3-Clause |  |
| [golang.org/x/exp](third_party/licenses/golang.org_x_exp@v0.0.0-20230522175609-2e198f4a06a1/) | `v0.0.0-20230522175609-2e198f4a06a1` | BSD-3-Clause |  |
| [golang.org/x/net](third_party/licenses/golang.org_x_net@v0.11.0/) | `v0.11.0` | BSD-3-Clause |  |
| [golang.org/x/sync](third_party/licenses/golang.org_x_sync@v0.3.0/) | `v0.3.0` | BSD-3-Clause |  |
| [golang.org/x/sys](third_party/licenses/golang.org_x_sys@v0.30.0/) | `v0.30.0` | BSD-3-Clause |  |
| [golang.org/x/text](third_party/licenses/golang.org_x_text@v0.10.0/) | `v0.10.0` | BSD-3-Clause |  |
| [golang.org/x/time](third_party/licenses/golang.org_x_time@v0.10.0/) | `v0.10.0` | BSD-3-Clause |  |
| [golang.zx2c4.com/wintun](third_party/licenses/golang.zx2c4.com_wintun@v0.0.0-20230126152724-0fa3db229ce2/) | `v0.0.0-20230126152724-0fa3db229ce2` | MIT |  |
| [google.golang.org/protobuf](third_party/licenses/google.golang.org_protobuf@v1.30.0/) | `v1.30.0` | BSD-3-Clause |  |
| [gopkg.in/ini.v1](third_party/licenses/gopkg.in_ini.v1@v1.67.0/) | `v1.67.0` | Apache-2.0 |  |
| [gopkg.in/yaml.v3](third_party/licenses/gopkg.in_yaml.v3@v3.0.1/) | `v3.0.1` | MIT / Apache-2.0 | MIT for the libyaml port files; Apache-2.0 for the remaining files. NOTICE included. |
| [modernc.org/libc](third_party/licenses/modernc.org_libc@v1.24.1/) | `v1.24.1` | BSD-3-Clause | Includes `honnef.co/go/netdb` under MIT. |
| [modernc.org/mathutil](third_party/licenses/modernc.org_mathutil@v1.5.0/) | `v1.5.0` | BSD-3-Clause |  |
| [modernc.org/memory](third_party/licenses/modernc.org_memory@v1.6.0/) | `v1.6.0` | BSD-3-Clause |  |
| [modernc.org/sqlite](third_party/licenses/modernc.org_sqlite@v1.25.0/) | `v1.25.0` | BSD-3-Clause |  |

Total runtime modules: 67.

## License obligations

- **GPL-3.0-or-later**: the project itself. Redistribution of binaries or modified source must comply with GPLv3.
- **GPL-3.0**: `github.com/nadoo/ipset` (replaced source). Keep its license text and do not relicense that component.
- **Apache-2.0**: keep the license text and any `NOTICE` file; state changes made to the files.
- **MPL-2.0**: `github.com/hashicorp/hcl` is file-level copyleft; modified MPL files must stay under MPL-2.0.
- **MIT / BSD / ISC / Zlib / Unlicense**: keep the copyright and permission notice in the distribution.

This file is an inventory, not legal advice. If you redistribute a modified binary, review the upstream license texts and preserve the notices in `third_party/licenses/`.
