# Building mosdns-v4

[简体中文](build.cn.md) | English

## Requirements

- Go **1.20.x**. The module declares `go 1.20`; newer toolchains can break
  `github.com/quic-go/quic-go v0.35.1` before the build even starts.
- Git, and a host with enough disk for ten cross-compiled binaries.
- `CGO_ENABLED=0` is the supported build mode. No C compiler is required.
- Running `fakeip_nat` with `use_tun` still needs root/administrator rights at
  runtime, but not at build time.

```bash
git clone https://github.com/ersonw/mosdns-v4.git
cd mosdns-v4
go version
```

## Local build

```bash
CGO_ENABLED=0 go build -trimpath -o build/mosdns .
./build/mosdns version
```

The binary reports the value stored in `main.version`. Without an injected
version it reports `dev`.

## Inject a version

```bash
CGO_ENABLED=0 go build -trimpath \
  -ldflags "-s -w -X main.version=v4.0.1" \
  -o build/mosdns .
./build/mosdns version
```

`-version` is only a label. It does not change the source tree or the asset
name.

## Cross build

`release.py` is the entry point. With no target it builds every supported
target; with target arguments it builds only those targets:

```bash
python3 release.py
python3 release.py linux/amd64
python3 release.py linux/amd64 windows/amd64
python3 release.py linux-amd64 --version v4.0.1
python3 release.py --list
```

Targets accept `GOOS/GOARCH` or the asset form `GOOS-GOARCH`. The script
delegates to `tools/crossbuild` and writes outputs to `build/`.

```bash
go run ./tools/crossbuild -version v4.0.1
go run ./tools/crossbuild linux/amd64 windows/amd64
```

Output names are stable and do not contain the version:

```text
build/mosdns-linux-amd64
build/mosdns-linux-arm64
build/mosdns-darwin-arm64
build/mosdns-windows-amd64.exe
```

Targets: `darwin-arm64`, `darwin-amd64`, `linux-amd64`, `linux-arm64`,
`linux-armv6`, `linux-armv7`, `linux-386`, `linux-ppc64le`, `freebsd-amd64`,
`windows-amd64`.

## Tests and checks

```bash
go vet ./...
go test ./coremain/ ./plugin/executable/fakeip_nat/ ./plugin/executable/telegram_bot/ ./tools/crossbuild/ -count=1
go test ./...
```

`go test ./...` covers the whole module and is slower. The CI subset is the
command above with four packages. Run both before a release when the toolchain
matches `go.mod`.

## Release

Pushing a `v*` tag triggers `.github/workflows/release.yml`:

```bash
git tag v4.0.2
git push origin v4.0.2
```

The workflow calls `go run ./tools/crossbuild -version "${VERSION}"`, copies
assets as `mosdns-<target>[.exe]`, writes `SHA256SUMS.txt`, and publishes them
to the matching GitHub Release. GitHub already attaches source archives for the
tag, so the workflow does not create its own copies.

Stable latest download:

```text
https://github.com/ersonw/mosdns-v4/releases/latest/download/mosdns-linux-amd64
https://github.com/ersonw/mosdns-v4/releases/latest/download/SHA256SUMS.txt
```

## Related

- [Install and run](install.md)
- [Usage](usage.md)
- [Licensing](licensing.md)
