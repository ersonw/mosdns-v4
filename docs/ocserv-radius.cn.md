# ocserv 与 RADIUS：vhost 到底传了什么

排查「另一个 ocserv 连同一个 RADIUS 找不到用户」时的结论。源码取自 ocserv
master 分支（`src/auth/radius.c`、`src/subconfig.c`），插件部分取自本仓库
`plugin/executable/radius/`。

## 结论

**ocserv 不会把 vhost 名字传给 RADIUS。** 用户名也不会带 vhost 前后缀。

Access-Request 里固定发送的属性：

| 属性 | 取值 |
| --- | --- |
| User-Name (1) | 用户输入的名字，原样 |
| User-Password (2) / CHAP-Password (3) | 密码；PAP 或 CHAP |
| NAS-IP-Address (4) / NAS-IPv6-Address | 本次连接的本地地址 `pctx->our_ip` |
| Calling-Station-Id | 客户端公网地址 |
| Acct-Session-Id (44) | 会话 ID（认证时也带，便于与计费关联） |
| Connect-Info | 客户端 UA |
| Service-Type (6) / NAS-Port-Type | 固定 Authenticate-Only / Async |
| NAS-Identifier (32) | **仅当 `auth` 里显式配置 `nas-identifier=` 才发送** |

`nas-identifier` 的值是配置里原样拷贝的静态字符串，ocserv 不会把 vhost 域名
替换进去（`src/subconfig.c` 直接把括号内值赋给 `additional->nas_identifier`）。

## vhost 的真实作用

vhost 决定的是 **ocserv 用哪一段配置**（哪套 `auth`、哪个 `radiusclient.conf`、
哪个服务端地址、哪份证书），而不是在同一个 RADIUS 用户表里加一个租户维度。

vhost 的选取依据是客户端 TLS 握手的 **SNI**，必须与 vhost 的 `domain` 完全一致；
用 IP 连接时没有 SNI，一律落到 default context。

## 本插件的现状

`plugin/executable/radius/` 是一张全局表，按用户名精确匹配：

```sql
CREATE TABLE radius_users (name TEXT PRIMARY KEY, password, group_name, ip, ...)
```

`handleAccess` 只读 User-Name 与 User-Password（或据此判断 CHAP），成功时回写
Class 作为分组；`attrNASIdentifier`、`attrNASIPAddress`、`attrNASPort` 常量虽然
在 `radius_packet.go` 中定义，但没有任何读取点。

因此：即使 ocserv 配置了 `nas-identifier`，插件也不会据此区分来源；账号始终是
全局的。要按 vhost 隔离，只能给每个 vhost 指向不同的 RADIUS 实例/不同 `db_path`，
或修改插件为账号表增加 vhost 维度。

## 现场排查案例

同一个镜像派生出多台节点，hostname 与 machine-id 相同，容易误判为同一台机器。
判断依据应是各自出口公网地址，而不是 hostname。

失败节点的关键日志：

```
sec-mod: using 'plain' authentication to authenticate user
error in plain authentication; cannot open: /run/ocserv/default/ocpasswd
```

配合生成配置可见：default context 是 `auth = "plain[/run/ocserv/default/ocpasswd]"`，
而该文件不存在；radius 只配置在 `[vhost:...]` 段。也就是说认证请求落在 vhost 0，
根本没有进入 RADIUS。

检查顺序：

1. `grep -nE "auth =|acct =|\[vhost" /run/ocserv/ocserv.conf` 看每个 context 的认证方式；
2. `journalctl -u ocserv | grep -i "vhost"` 确认目标 vhost 是否成功加载
   （改域名/端口后若报 `no ipv4-network or ipv6-network options set`，该 vhost 未生效）；
3. 抓包确认是否真的发出 RADIUS 请求：`tcpdump -i any -n -vv udp port 1812`；
4. 客户端使用 vhost 的 `domain` 连接（证书 SAN 需覆盖该名字），不要用 IP。

## 参考

- ocserv `src/auth/radius.c`：Access-Request 属性构造
- ocserv `src/subconfig.c`：`nas-identifier=` 取值
- 本仓库 `docs/plugins/radius.cn.md`：插件参数与账号管理
