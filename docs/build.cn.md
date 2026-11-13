# 编译 mosdns-v4

[English](build.md) | 简体中文

## 环境要求

- Go **1.20.x**。`go.mod` 标注 `go 1.20`，更高版本的 Go 可能在编译开始前就与
  `github.com/quic-go/quic-go v0.35.1` 不兼容。
- Git，以及足够存放十个交叉编译产物的磁盘空间。
- 使用 `CGO_ENABLED=0`，不需要 C 编译器。
- `fakeip_nat` 的 `use_tun` 在运行时需要 root/管理员权限，编译时不需要。

```bash
git clone https://github.com/ersonw/mosdns-v4.git
cd mosdns-v4
go version
```

## 本地编译

```bash
CGO_ENABLED=0 go build -trimpath -o build/mosdns .
./build/mosdns version
```

二进制显示 `main.version` 的值；未注入时显示 `dev`。

## 注入版本号

```bash
CGO_ENABLED=0 go build -trimpath \
  -ldflags "-s -w -X main.version=v4.0.1" \
  -o build/mosdns .
./build/mosdns version
```

`-version` 只影响二进制内部显示的版本，不改变源码，也不参与发布资产命名。

## 交叉编译

`release.py` 是统一入口：不传目标参数时编译全部支持目标，传入目标时只编译指定
目标：

```bash
python3 release.py
python3 release.py linux/amd64
python3 release.py linux/amd64 windows/amd64
python3 release.py linux-amd64 --version v4.0.1
python3 release.py --list
```

目标参数支持 `GOOS/GOARCH` 和资产名 `GOOS-GOARCH` 两种写法。脚本内部调用
`tools/crossbuild`，产物写入 `build/`。

```bash
go run ./tools/crossbuild -version v4.0.1
go run ./tools/crossbuild linux/amd64 windows/amd64
```

产物名固定，不带版本号：

```text
build/mosdns-linux-amd64
build/mosdns-linux-arm64
build/mosdns-darwin-arm64
build/mosdns-windows-amd64.exe
```

目标列表：`darwin-arm64`、`darwin-amd64`、`linux-amd64`、`linux-arm64`、
`linux-armv6`、`linux-armv7`、`linux-386`、`linux-ppc64le`、`freebsd-amd64`、
`windows-amd64`。

## 测试与检查

```bash
go vet ./...
go test ./coremain/ ./plugin/executable/fakeip_nat/ ./plugin/executable/telegram_bot/ ./tools/crossbuild/ -count=1
go test ./...
```

`go test ./...` 覆盖整个模块，耗时更长；CI 使用上面的四个包子集。发布前在
与 `go.mod` 匹配的 Go 版本下运行两者。

## 发布

推送 `v*` 标签会触发 `.github/workflows/release.yml`：

```bash
git tag v4.0.2
git push origin v4.0.2
```

工作流执行 `go run ./tools/crossbuild -version "${VERSION}"`，把资产复制为
`mosdns-<target>[.exe]`，生成 `SHA256SUMS.txt`，附加到同名 GitHub Release。
GitHub 会为标签自动生成源码压缩包，工作流不再重复打包。

固定最新版下载地址：

```text
https://github.com/ersonw/mosdns-v4/releases/latest/download/mosdns-linux-amd64
https://github.com/ersonw/mosdns-v4/releases/latest/download/SHA256SUMS.txt
```

## 相关文档

- [安装与运行](install.cn.md)
- [配置与运维](usage.cn.md)
- [授权说明](licensing.cn.md)
