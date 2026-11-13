[English](radius.md) | 简体中文

# radius
给 ocserv 当 RADIUS 服务端：账号由插件自己存在本地 SQLite，不再从 ocserv 的 `ocpasswd` 读。
ocserv 打开 `auth = radius` 后发 `Access-Request`（PAP），插件校验用户名、密码与启用状态，
通过时把账号的 group 作为 `Class` 属性回给 ocserv；账号配置了固定 IP 时再回
`Framed-IP-Address(8)`，ocserv 每次登录都给该用户同一个隧道地址。打开记账后同时收 `Accounting-Request`，
在 `radius_sessions` 里记录每个会话的起止时间、客户端地址与收发字节。每个账号还累计上下行
流量（`used_in` / `used_out`），可以设置总流量上限（`max_total`，0 表示无限制）和重置周期
（`reset_period`，0 表示不自动重置）。每次 interim/stop 只把该会话新产生的字节加进账号，
重复记录不会重复计费；累计达到上限时账号自动禁用，周期到点后清零并只恢复因配额被禁用的账号。
`Acct-Input/Output-Gigawords` 会与低 32 位合成为 64 位总量，长会话不会在 4 GiB 处回绕。
只实现 PAP：若客户端协商成 EAP-MSCHAPv2，ocserv 发来的是 `CHAP-Password`，插件明确回 Reject
并提示改用 PAP，不会静默丢包。密码按 PBKDF2-HMAC-SHA256（12000 轮加盐）存，明文不落盘；
账号的增删改由 `telegram_bot` 的 `/user` 完成，固定 IP 用 `/user ip <name> <ipv4|->`
设置或清除（`-` 表示清除固定 IP）。流量上限用 `/user limit <name> <max|0|-> [period|0|-]`
设置（`0` / `-` 表示无限制或永不重置，`period` 支持 `30d` / `168h`；省略 `period` 保留当前重置周期），`/user usage <name>`
看上下行和剩余额度，`/user reset <name>` 立即清零并重新开始周期。配置 `ocserv_config` 后，新增账号会自动从 ocserv 的
`ipv4-network` 分配一个固定地址：从池高端向下找空闲地址，ocserv 自己的 tun 地址（默认首个
可用地址，或 `ipv4-network = 10.9.0.1/24` / `server-ip` 显式写出的地址）不参与分配。
```yaml
  - tag: radius
    type: radius
    args:
      listen: 0.0.0.0:1812             # 认证端口
      accounting_listen: 0.0.0.0:1813  # 记账端口，off / 0 关闭
      secret: "换成一串随机字符"        # 必填，必须与 ocserv 的 secret 一致
      db_path: etc/mosdns/radius.db    # 账号与会话表
      # 新增账号自动分配固定 IP：读 ocserv.conf 的 ipv4-network 作为分配池
      ocserv_config: /run/ocserv/dyize/ocserv.conf
      # 可选：手动指定池，优先于 ocserv_config；CIDR 或 起始-结束
      # ip_pool: "10.9.0.2-10.9.0.254"
      timezone: Asia/Shanghai           # 展示账号与会话时间用的时区
```
老库（`radius_users` 还没有 `ip` 列）在插件启动时自动补列，不需要手工迁移；固定 IP 由
`ip <> ''` 的部分唯一索引约束，同一个地址不能同时绑两个账号。
ocserv 侧对应（版本不同，段名可能是 `radius server` / `radius secret`，以本机 `ocserv.conf` 注释为准）：
```ini
auth = radius
radius[0].server = 127.0.0.1
radius[0].secret = 换成一串随机字符
radius[0].auth = pap
accounting[0].server = 127.0.0.1
accounting[0].secret = 换成一串随机字符
```
