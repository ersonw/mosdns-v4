[English](telegram_bot.md) | 简体中文

# telegram_bot
长轮询 Telegram Bot，用来在没有 SSH 的场合看状态、改配置、跑脚本。启动即开始拉取
`getUpdates`，`token` 缺失或 `chat_ids` 为空时插件保持禁用（不建连、不占线程）。每个 chat 绑定
一个角色，角色决定它能发哪些命令；只列在 `chat_ids` 里的 chat 用 `default_role`（默认 `admin`）。
两个角色是内置的，不必在 `roles` 里声明：`admin` 只能查看状态、管理 RADIUS 用户、查看和操作
ocserv、导出指定用户的访问记录、管理 `data_providers` 域名列表（`status`/`ocserv`/`radius`/`access`/`provider`）；
`superadmin` 继承 `admin`，并附加其余全部权限。
常用命令：`/status`、`/net`（数据面观测：tun 设备、代理是否生效、打标与表号、本插件在
`ip rule show` 里的规则、出口表的 default、nft 标记集合大小）、`/ledger`（账本里记了哪些待清理对象）、
`/sweep`（按账本删掉当前配置不拥有的残留，`kill -9` 之后可以手动收尾）、`/diag <domain>`（一次诊断：
假 IP、已学到的真实 IP、出口是代理还是 `next_hop`）、`/fip`（查看或切换 fakeip_nat 的映射，`/fip <tag> <sub>` 指定插件）、
`/vpn`（查 ocserv 在线用户、按网段分配固定 IP、reload/restart 服务、回看上下线事件）、`/user`（增删改 RADIUS 账号、用 `/user ip` 绑定固定 IP、用 `/user limit <name> <10GB|0|-> [30d|0|-]` 设置流量上限与重置周期、用 `/user usage <name>` 查看上下行用量、用 `/user reset <name>` 手动清零、查记账会话）、`/config`（读写 mosdns 配置字段）、`/provider`（按 `data_providers` 节点增/改/删/清空域名，`.txt` 还可分页列出）、`/exec`（跑白名单脚本）、
`/proxy`（读或写 fakeip 的出口代理，`/proxy on <url>` / `/proxy off`，写完要 `/reload confirm`）、
`/help`（只列出当前 chat 有权限执行的命令，并按组隐藏整组；`/help` 本身不受权限限制）、
`/audit`（最近的管理动作：谁在什么时候改了配置或跑了脚本，写 `telegram_bot_audit.log`，只记键路径不记值）、
`/reload`（给进程发关闭信号，靠外部 supervisor 重新拉起）、
`/access <user|ip> [days]`（按 RADIUS 用户（取其记账会话里的地址）或直接给地址，从 fakeip 的访问记录
里取出该地址访问过的域名/真实 IP，生成 `.xlsx` 发回请求的管理员；默认 7 天，最多 365 天）。
`proxy` 可让 API 请求走
HTTP(S)/SOCKS5 代理，`api_base` 便于指向镜像或测试端点。
插件之间通过 `fakeip_tags` / `ocserv_tags` / `radius_tags` 定位目标：列表第一个是默认，
其余用命令的第一个参数点名（如 `/fip <tag> stats`）。这三项是列表，不再接受单值写法。
```yaml
  - tag: tg
    type: telegram_bot
    args:
      token: "123456:ABCDEF"             # @BotFather 给的 token，缺失则不启用
      chat_ids: [123456789]              # 允许交互的 chat，空则不启用
      admins:
        - chat_id: 123456789
          role: superadmin                # 内置：继承 admin + 其余全部权限
        - chat_id: 987654321
          role: admin                     # 内置：状态 + 用户 + ocserv + 访问记录导出
      roles:                              # 自定义角色，可 inherits: [admin] 复用内置角色
        ops:
          allow: [status, fakeip, ocserv]
      default_role: admin                 # 只列在 chat_ids 里的 chat 用这个角色
      fakeip_tags: ["fakeip"]             # /fip 可管理的 fakeip_nat 插件 tag
      ocserv_tags: ["ocserv_user"]        # /vpn 可查询的 ocserv_ctl 插件 tag
      radius_tags: ["radius"]             # /user 可管理的 radius 插件 tag
      config_path: etc/mosdns/config.yaml # /config 改写的文件，留空取 -c 参数
      domain_manage_script: scripts/domain_manage.py # 默认 <配置目录>/scripts/，缺失自动下载
      txt2dat_script: scripts/txt2dat.py             # 默认 <配置目录>/scripts/，缺失自动下载
      domain_python: python3              # *.py 使用这个解释器
      domain_timeout: 30                  # 单次脚本超时（秒）
      audit_log: ""                       # 审计日志，留空取配置目录下 telegram_bot_audit.log
      proxy: ""                           # 例如 socks5://127.0.0.1:1080
      api_base: https://api.telegram.org
      poll_timeout: 30
      timezone: Asia/Shanghai            # 留空则跟随数据源插件，最终兜底上海时区
```

`domain_manage_script` 和 `txt2dat_script` 的相对路径按配置文件所在目录解析；
留空时默认使用 `<配置目录>/scripts/domain_manage.py` 和
`<配置目录>/scripts/txt2dat.py`。脚本不存在时，Bot 启动阶段会从仓库 raw 链接
`.../etc/mosdns/scripts/` 下载到该目录；下载失败只记录告警，不阻止 Bot 启动。
