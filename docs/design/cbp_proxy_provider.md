# CBP 代理 provider 闭环落地设计

旧版 `proxy_provides.md` 已删除。本稿按新流程重写，不保留旧的两段式目录校验方案。

### 参考实现

- `customBrowser/internal/network/cbpdirectory.go`：主服务端 `/v1/edge/bootstrap`、`server.candidates`（主服务端 TCP 候选）、CBP 节点目录解析。
- `customBrowser/internal/workspace/candidates.go`：主服务端 TCP 候选的 ICMP 探测、TCP 兜底、最低 RTT 选择。
- `customBrowserServer/internal/coord/client_role.go`：`HELLO -> CLIENT_AUTH -> CLIENT_READY -> NODE_LIST`。
- `customBrowserServer/pkg/coordclient/client.go`：coordinator 客户端封装。
- `mosdns-v4/pkg/egress/cbp`：现有 CBP raw-IP 客户端，只作为显式 `raw_ip_data` 的可选路径，不作为默认 stream 路径。


## 1. 目标链路

### 1.1 三个标识

| 标识 | 示例 | 含义 |
|---|---|---|
| 协议插件 tag | `cbp_proxy` | `plugins:` 里的插件 tag，也是 `egress_route.proxy` 的第一段 |
| 根配置 tag | `cbp_sg` | `proxy_provides[].tag`，代表一套主服务端配置 |
| CBP 节点 ID | `edge-sg-1` | 主服务端 TCP 接口 `NODE_LIST` 里的 CBP 节点 ID |

出口配置：

```yaml
proxy: "cbp_proxy:cbp_sg:edge-sg-1"
```

### 1.2 闭环流程

```text
egress_route Init
  │
  ├─ 解析 proxy，切出协议插件 tag = cbp_proxy
  ├─ 调 cbp_proxy.NewProxyDialer("cbp_sg:edge-sg-1")
  │
  ▼
cbp_proxy
  │
  ├─ 解析 tag = cbp_sg，nodeID = edge-sg-1
  ├─ 查根配置 proxy_provides[cbp_sg] -> {domain, token}
  ├─ GET https://{domain}/v1/edge/bootstrap
  │     └─ 非桌面端 API Key：X-API-Key
  │     └─ 取 server.candidates 作为主服务端 TCP 候选（不是 CBP 节点）
  ├─ 对所有候选 IP:port 并发 ICMP 探测
  │     ├─ 选延迟最低且可达的候选
  │     └─ ICMP 不可用时用 TCP connect 兜底
  ├─ 连入选中的主服务端 9443
  │     ├─ 确保客户端身份文件存在
  │     ├─ TLS 1.3 + ALPN cbp-coord/1
  │     ├─ HELLO -> CLIENT_AUTH -> CLIENT_READY
  │     └─ NODE_LIST -> 最新 CBP 节点列表（唯一 CBP 节点来源）
  ├─ 节点列表写入内存映射表 nodeTables[cbp_sg]
  │
  ▼
同一个 cbp_proxy 实例，处理本次出口
  │
  ├─ 查 nodeTables[cbp_sg][edge-sg-1]
  ├─ 取节点的 ControlAddr / PublicTCPEndpoint
  ├─ cbpclient.Dial({ControlAddr, RelayAddr, RelayNodeID, IdentityFile})
  └─ 返回 egress.Dialer + 代理端点地址
  │
  ▼
egress_route
  ├─ egress.Probe
  ├─ p.dialer = 返回的 dialer
  ├─ p.proxy = 节点控制地址
  └─ 数据面 DialContext -> net.Conn
```

这里默认走 **CBP stream**：`DialContext` 内部调用 `cbpclient.OpenStream`，每个目标连接一条流。不是先起 gVisor raw-IP 栈。

这条链路里必须区分两类节点：

- **主服务端 TCP 候选**：HTTPS API 返回，是主服务端 coordinator/relay 的 `IP:port`，用于选主服务端入口。
- **CBP 节点**：只能从已认证的主服务端 TCP 接口 `NODE_LIST` 拿，用于最终出口。

`server.candidates` 不是 CBP 节点，不能写进 CBP 节点表。不再依赖 `/v1/edge/bootstrap` 的 `edge.payload` 签名目录，因此不需要 `public_key`。

### 1.3 两类节点必须分开

| 阶段 | 数据 | 来源 | 存放 |
|---|---|---|---|
| A | 主服务端 TCP 候选（coordinator/relay 入口，通常是 9443） | HTTPS `server.candidates` | `coordinatorCandidates`，只用于 ICMP 选主服务端 |
| B | CBP 节点（最终出口） | 主服务端 TCP 接口 `NODE_LIST` | `nodeTables[tag][nodeID]`，只用于出口拨号 |

约束：

- A 阶段的 `IP:port` 不能当 CBP 节点，不能塞进 `nodeTables`。
- B 阶段的节点不能拿去 ICMP 选主服务端。
- `proxy` 第三段 `nodeID` 只在 B 阶段查。
- `server.candidates` 为空只影响“选哪个主服务端”，不影响 CBP 节点是否存在；CBP 节点为空则 `NODE_LIST` 失败。


---

## 2. 根配置

### 2.1 配置形态

```yaml
proxy_provides:
  - tag: cbp_sg
    domain: https://api.example.com
    # api.aa2.dev / api.aa3.dev 可省略 token / node_token，使用代码内置初始凭据
    token: ""                         # HTTPS bootstrap + identity
    node_token: ""                    # CBP 节点 AUTH
    # identity_file: /etc/mosdns/proxy_provides/cbp_sg.json  # 可选
    # config_dat: /etc/mosdns/proxy_provides/cbp_sg.dat      # 可选；不传则首次成功后自动生成

  - tag: cbp_hk
    domain: https://hk-api.example.com
    token: ""
```

字段：

| 字段 | 必填 | 说明 |
|---|---|---|
| `tag` | 是 | 唯一，不能重复，不能包含冒号；只用于命名这套主服务端入口 |
| `domain` | 是 | 主服务端 HTTPS 地址；只允许 `https`，没有 scheme 时补 `https://` |
| `token` | 否 | 非桌面端 API 密钥；非空时只发送 `X-API-Key: <token>`，不发 `Authorization`，`api.aa2.dev` / `api.aa3.dev` 为空时使用内置初始凭据 |
| `node_token` | 否 | CBP 节点 `AUTH` 的 token；内置 host 为空时使用内置凭据，否则回落到 `token` |
| `identity_file` | 否 | 客户端身份文件路径；不传时默认 `{config_dir}/proxy_provides/{tag}.json`。文件存在时其 `client_id` 优先于 `tag` |
| `config_dat` | 否 | 桌面客户端 `custombrowser.config.proto/v1` 的 `.dat`；读取 `network.cbp`，YAML 显式字段优先。支持 portable `CBCFG1`、裸 proto 和带 `config_key_file` 的 runtime `CBCFG2`。不传时默认 `{config_dir}/proxy_provides/{tag}.dat`。无论默认还是显式路径，文件不存在都不算启动错误，首次成功拿到 `NODE_LIST` 后在该路径自动生成。默认路径和 `{config_dir}/proxy_provides/` 下的 `.dat` 由本插件管理，节点表变化时会原子重写；显式指向其他位置的已有 `.dat` 只读，不覆盖 |
| `config_key_file` | 否 | runtime `CBCFG2` 用的 base64/hex 32 字节 CustomBrowser DB key；`CBCFG1` 忽略 |
| `insecure` | 否 | TLS 校验覆盖；不填时使用 `config_dat` 的 `insecure_skip_verify` |

`identity_file` 不要求预先存在。首次启动发现文件不存在时，自动走 `/v1/identity/client` 申请并原子写入；权限 `0600`。配置文件入口只是覆盖默认路径，不改变自动生成行为。

`config_dat` 同样允许不存在。启动阶段先解析出最终路径：没写就用默认路径，写了就用配置路径；`os.Stat` 发现文件不存在时只记下 `GenerateDat=true`，不会因为缺文件失败。第一次 `NODE_LIST` 成功后，把当前 `tag`、`domain`、`token`、`node_token`、`identity_file`、`insecure` 和节点表写成 portable `CBCFG1` 的 `ConfigDocument`，权限 `0600`，原子替换。之后启动会直接读回这个文件。

不需要在 YAML 写 `GenerateDat`；它是内部字段（`yaml:"-"`），由文件存在性检查自动设置。

受管理 `.dat`（默认路径，或显式放在 `{config_dir}/proxy_provides/` 下）和桌面端一样，以最新 `NODE_LIST` 为准：节点 ID 消失就从文件删除，新 ID 加入，ID/区域/地址/label 变化则更新；写盘前先比较节点表指纹，只有变化时才原子重写，避免每 5 分钟无意义写文件。节点 label 为空时写 ID。`config.dat` 中不保留旧节点，也不做旧 ID 到新 ID 的别名迁移。

显式指向其他位置的已有 `.dat` 视为桌面客户端的文件，只读取、不重写；如果它在启动时不存在，本进程首次成功后会生成一次，但后续刷新不再管理。

### 2.2 校验规则

- `tag` 必须匹配 `^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`，和服务端 `client_id` 规则一致。
- `domain` 只接受 `https://`；拒绝 `http://`、空 host、带 fragment 的地址。
- `domain` 统一去掉末尾 `/`，再拼 `/v1/edge/bootstrap`；如果已经包含该路径，直接使用。
- `token` 只做 trim；空字符串是合法值。
- 重复 `tag` 在启动阶段直接失败，不能留到第一次拨号。
- `proxy_provides` 支持写在 include 文件里，合并规则和 `data_providers` 一致：子配置在前，主配置在后。

### 2.3 token 为空时的行为

```go
if strings.TrimSpace(cfg.Token) != "" {
    req.Header.Set("X-API-Key", cfg.Token)
}
```

空 token 的语义是“HTTP 请求不带认证头”。非空时只发 `X-API-Key`，不发 `Authorization`，也不模拟桌面客户端的签名头。

---

## 3. egress_route 的 proxy 语法

```yaml
- tag: egress_sg
  type: egress_route
  args:
    proxy: "cbp_proxy:cbp_sg:edge-sg-1"
```

解析规则：

- 第一个冒号前：`cbp_proxy`，协议插件 tag。
- 第一个冒号后：`cbp_sg:edge-sg-1`，原样交给协议插件。
- 协议插件再切：`cbp_sg` 是根配置 tag，`edge-sg-1` 是节点 ID；ID 不命中时按节点 label 唯一匹配。

不要写成：

```yaml
proxy: "cbp_proxy://cbp_sg:edge-sg-1"
```

`url.Parse` 会把 `cbp_sg:edge-sg-1` 当成 `host:port`，节点名不是数字时直接报错。三段式没有 `//`，解析稳定。

内置 `socks5:`、`http:`、`https:`、`trojan:`、`cbp:` 等继续走原来的 `egress.New`。自定义协议插件 tag 不能和内置 scheme 重名。CBP 内置 scheme 已经叫 `cbp`，所以协议插件用 `cbp_proxy`，避免劫持 `cbp://...` 旧配置。

`cbp_proxy` 必须声明在 `egress_route` 之前。`egress_route` 初始化时会按第一段 tag 查 registry，插件还没注册就查不到。

---

## 4. 协议插件接口

在 `pkg/egress` 增加：

```go
// pkg/egress/provider.go
type Provider interface {
    // params 是第一个冒号之后的全部内容，例如 "cbp_sg:edge-sg-1"。
    // 返回的 Dialer 是数据入口：
    //   conn, _ := d.DialContext(ctx, "tcp", target)
    //   conn.Write(request)
    //   conn.Read(response)
    // proxyHost 是实际代理端点地址，egress_route 用它排除代理连接本身。
    NewProxyDialer(params string, insecure bool) (d Dialer, proxyHost string, err error)
}
```

**不要返回 `func([]byte) ([]byte, error)`。**

CBP 是长连接、双向流，承载 TCP/UDP/ICMP 的原始 IP 包。一次性 `[]byte` 函数无法表达连接生命周期、背压、半关闭和多次请求。这里返回 `Dialer`，调用方拿到的 `net.Conn` 就是“数据入口”：写入需要转发的数据，读取原始响应数据。

如果调用方只想要函数形态，可以包一层：

```go
type DialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// 等价于 d.DialContext
```

推荐保留 `Dialer` 接口，因为 `egress.Probe` / `Close` 可以直接复用，不需要再维护另一套生命周期。


如果某个协议本身是请求-响应型，也仍然实现 `Dialer`，在内部用 `net.Conn` 适配器把一次 `Write` 映射成一次请求、一次 `Read` 映射成对应响应；不要把这种语义暴露到 `egress_route`。

---

## 5. HTTPS 获取主服务端 TCP 候选

### 5.1 请求的是主服务端 TCP 候选，不是 CBP 节点

```http
GET https://api.example.com/v1/edge/bootstrap
Accept: application/json
X-API-Key: <token>                     # 非桌面端 API Key，token 非空时发送
```

非桌面端走管理 API Key（`cbak_...`），只放 `X-API-Key`，不发送 `Authorization`，也不模拟桌面客户端的身份签名头。`token` 为空时不发送认证头，服务端是否允许匿名目录由服务端决定。

`/v1/edge/bootstrap` 返回的是主服务端入口信息，不是 CBP 节点列表：

- `server.candidates`：主服务端 TCP 候选（coordinator/relay 的 `IP:port`）
- `server.coordinator_endpoint` / `server.coordinator_addresses`：单个主服务端入口或扁平入口列表
- `edge`：CBP 节点目录（本流程不使用；CBP 节点以 `NODE_LIST` 为准）

### 5.2 主服务端 TCP 候选结构

```json
{
  "server": {
    "public_ip": "203.0.113.10",
    "candidates": [
      {
        "id": "main",
        "role": "main",
        "addresses": ["203.0.113.10:9443", "10.0.0.10:9443"],
        "public_ip": "203.0.113.10"
      },
      {
        "id": "relay-sg",
        "role": "relay",
        "addresses": ["198.51.100.20:9443"],
        "public_ip": "198.51.100.20"
      }
    ]
  }
}
```

候选地址归一化：

- 这些 `addresses` 是主服务端 coordinator/relay 的 TCP 入口，不是 CBP 节点的 8443/QUIC 端点。
- `addresses` 里的 `host:port`
- `endpoint` 里的 `tls://host:port`
- `coordinator_endpoint` 里的 `tls://host:port`
- `coordinator_addresses` 里的扁平 `host:port`

非法地址、没有端口的地址、重复地址直接丢弃。

### 5.3 认证边界

目录请求走非桌面端 API Key：

- `X-API-Key: cbak_...`

服务端对未带桌面客户端签名头的请求接受静态部署 token、管理员会话或 API Key；但 API Key 只从 `X-API-Key` 读取，`Authorization: Bearer cbak_...` 不作为 API Key 接受。`cbak_` 密钥建议使用默认 `nodes.read` 权限。这里不发送 `X-CustomBrowser-Client-ID` / `Timestamp` / `Signature`，也不发送 `Node-Sync`，避免把 CBP provider 伪装成桌面客户端。

`proxy_provides.token` 必须是服务端能通过 `X-API-Key` 校验的密钥；内置 `api.aa2.dev` / `api.aa3.dev` 已换成 `cbak_` 管理 API Key。旧的静态部署 token 只走 `Authorization`，不适用于当前只发 `X-API-Key` 的请求路径。

### 5.4 客户端身份文件

coordinator 的 `CLIENT_AUTH` 和 CBP 节点的 `AUTH` 都需要 Ed25519 客户端身份。根配置只有 `tag/domain/token`，身份文件按以下规则定位：

```text
identity_file = 根配置 identity_file
                ?? {config_dir}/proxy_provides/{tag}.json
client_id     = tag
```

启动或首次拨号时：

1. 文件存在：`cbpidentity.LoadOrIssueClient` 直接加载扁平 `client_id/public_key/private_key`，coordinator 和 CBP 共用这一份私钥。
2. 文件不存在：
   ```http
   POST https://{domain}/v1/identity/client
   Content-Type: application/json
   Authorization: Bearer <token>   # token 为空时不加这个头

   {"client_id":"cbp_sg"}
   ```
   返回 `client_id/public_key/private_key`，原子写入 `identity_file`，权限 `0600`。
3. 文件不存在且 `token` 为空：仍会匿名请求签发；服务端要求认证时返回 401，启动失败并保留响应体。
4. `token` 是非桌面端管理 API Key（`cbak_...`）且身份文件不存在时，目录请求可以通过，但 `POST /v1/identity/client` 只接受静态部署 token，签发会失败。这种场景需要预先放入身份文件，或改用静态部署 token 完成首次签发。
5. 文件存在但 coordinator/CBP 认证失败：当前直接报错，不自动删除旧身份重签。确认是 key 不匹配后，删除 `identity_file` 再启动。
6. 身份文件只支持扁平格式；`customBrowserServer` 的 standalone `cbpserver keygen` 嵌套 bundle 和 `node.auth_token` 尚未接入，`proxy_provides.token` 同时作为 HTTP token 与 CBP `AUTH` token。


目录请求不再使用客户端身份签名；身份文件只用于 coordinator 的 `CLIENT_AUTH` 和 CBP 节点的 `AUTH`。已有身份时，目录请求可以使用 `cbak_` API Key，不受身份文件影响。

`domain` 可以写成 API 基址，也可以写成完整的 `https://.../v1/edge/bootstrap`；后者会剥掉 bootstrap 后缀再拼身份接口。身份申请和 coordinator 拨号仍假设同域。


---

## 6. 主服务端 TCP 候选的 ICMP 选择

### 6.1 探测主服务端 TCP 候选

对所有主服务端 TCP 候选地址并发探测：

```text
host, port = SplitHostPort(address)
icmp RTT = ICMP Echo(host), timeout 1.2s
if ICMP 不可用或超时:
    tcp RTT = TCP connect(host:port), timeout 1.2s
```

规则：

- ICMP 优先，符合“先用 ICMP 包进行延迟测试”。
- ICMP 被防火墙过滤、无 raw socket 权限、或平台不支持时，才用 TCP connect 兜底。
- 只有 RTT > 0 且无错误的结果才算“可连通”。
- 所有候选都不可达时，启动失败；不要随便拿第一个候选继续。

### 6.2 主服务端候选排序

```text
1. 可达优先
2. RTT 低优先
3. RTT 相同时，role=main 优先于 relay
4. 仍相同，公网地址优先于内网地址
```

最终产出：

```go
type CoordinatorChoice struct {
    CandidateID string
    Address     string // host:port
    Endpoint    string // tls://host:port
    ServerName  string
    Role        string
    RTT         time.Duration
    ProbeKind   string // icmp | tcp
}
```

`ServerName` 取候选的 `public_ip`，没有则取地址 host。CBP coordinator 的证书按 IP 签发时，TLS 校验使用这个值；`insecure` 默认 false，只有显式配置才跳过。

### 6.3 没有候选时的兜底

按顺序：

1. `server.candidates`
2. `server.coordinator_addresses` 合成一个虚拟候选
3. `server.coordinator_endpoint`

三者都没有，直接报错“主服务端未发布可用连接节点”。

---

## 7. 通过主服务端 TCP 接口获取 CBP 节点列表

### 7.1 TCP 接口与协议

选中主服务端 TCP 候选后连：

```text
TCP -> TLS 1.3 -> ALPN "cbp-coord/1"
```

握手消息：

```text
S: HELLO {protocol:"cbp-coord/1", nonce}
C: CLIENT_AUTH {client_id, public_key, signature(nonce)}
S: CLIENT_READY {client_id, regions, node_count}
S: NODE_LIST {nodes:[...]}
```

`signature` 是 Ed25519 对 nonce 的签名，使用客户端身份文件里的私钥。

### 7.2 最小 coordinator 客户端

`mosdns-v4` 不直接依赖 `customBrowserServer` 的内部包，新增：

```text
pkg/cbpcoord/
  client.go      // TLS、HELLO、CLIENT_AUTH、CLIENT_READY、NODE_LIST
  protocol.go    // 帧类型和 payload 结构
  node.go        // NodeList -> 可拨号节点
```

只实现“取一次 NODE_LIST 后关闭”的最小客户端，不实现 25 秒心跳、UDP rendezvous、relay 和 `Run` 循环。节点列表按 TTL 重新拉取，不保持长连接。

### 7.3 NODE_LIST 的 CBP 节点结构

```go
type Node struct {
    ID                string
    Label             string // 显示名，仅作为出口配置的匹配别名
    Region            string
    Endpoint          string
    PublicAddr        string
    LANEndpoint       string
    TCPEndpoint       string
    LANTCPEndpoint    string
    PublicEndpoint    string
    PublicTCPEndpoint string
    PublicKey         string
    Weight            int
    Load              float64
}
```

控制地址推导：

1. `PublicTCPEndpoint` 优先。
2. 没有时用 `PublicAddr` + `TCPEndpoint` 的端口。
3. 再没有时用 `TCPEndpoint`。
4. LAN 地址只作为 CBP 节点地址的本地兜底，不作为默认。

`cbp.Dial` 使用 `host:port`，不带 `tls://` 前缀。

---

## 8. CBP 节点内存映射表

### 8.1 CBP 节点表数据结构

```go
type ProviderState struct {
    Config        ProxyProvideConfig
    IdentityPath  string
    Nodes         map[string]Node
    Coordinator   CoordinatorChoice
    RefreshedAt   time.Time
    Refreshing    bool
    LastErr       error
}

type NodeTable struct {
    mu       sync.RWMutex
    byTag    map[string]*ProviderState
    refresh  map[string]*sync.Mutex // 每个 tag 一把刷新锁
}
```

- key 第一层：`proxy_provides[].tag`
- key 第二层：CBP 节点 ID（只来自 `NODE_LIST`）
- `server.candidates` 只存在 `coordinatorCandidates`，不能写入 `nodeTables`
- 运行时权威表只存内存；受管理的 `config.dat` 保存一份节点快照，但启动时仍以在线 `NODE_LIST` 为准
- 身份文件落盘

### 8.2 刷新

- TTL 默认 5 分钟。
- 出口拨号时检查 `RefreshedAt`：
  - 未过期：直接查表。
  - 已过期：同步刷新；同 tag 并发只允许一个刷新。
  - 刷新失败但旧表非空：继续用旧表，记录 warning。
  - 刷新失败且旧表为空：本次拨号失败，不降级到直连。
- 插件启动时起后台刷新循环，每分钟检查一次；发现 `RefreshedAt` 超过 5 分钟 TTL 就刷新。这样即使 `egress_route` 启动时只取一次 dialer，节点表和受管理 `.dat` 也会持续更新。
- 后台刷新与按需刷新共用每个 tag 的 `refreshMu`，不会并发重复拉取。
- 刷新成功后内存表整体替换，受管理 `.dat` 按节点表指纹决定是否原子重写；刷新失败保留旧表，不写盘。
- 刷新只影响下一次 `NewProxyDialer`；已经建立的出口继续使用它自己的 CBP session。运行期按请求切换节点需要动态 dialer，不在本版范围。

### 8.3 节点查找

```go
node, ok := state.Nodes[name]          // 先按 NODE_LIST 的 id 精确匹配
if !ok {
    // 再遍历 label；唯一命中才使用，重复 label 直接报错
}
```

节点选择值优先按节点 ID 精确匹配；ID 不命中时才回退到节点 `label`。两者都不命中、或 label 对应多个节点时立即报错，不做模糊匹配，也不回退到“第一个节点”。ID 命中优先于其他节点的同名 label；配置写错应该立刻暴露。

### 8.4 节点内地址顺序与 relay 回退

同一个节点可能同时发布 `PublicTCPEndpoint`、`TCPEndpoint`、`LANTCPEndpoint`。`Node` 不要只存一个 `ControlAddr`，要存有序地址集合：

```go
type Node struct {
    ID          string
    Addresses   []string // 公网优先，LAN 兜底
    RelayNodeID string
    ...
}
```

出口初始化时：

1. 对 `Addresses` 做 ICMP 探测；ICMP 不可用走 TCP connect。
2. 可达地址按 RTT 排序。
3. `DialContext` 按顺序尝试；第一个成功的地址建立 CBP stream。
4. 所有直连地址都失败时，使用 `RelayAddr = 选中的主服务端 host:port`、`RelayNodeID = node.ID` 走主服务端 relay。
5. 不做“换一个 nodeID”的跨节点回退；nodeID 是用户显式指定的，换节点会改变出口语义。

这样既保留“指定节点”的确定性，又能覆盖 NAT 节点和多地址节点。

---

## 9. 出口调用与 CBP 拨号

### 9.1 协议插件解析

```go
func (p *Plugin) NewProxyDialer(params string, insecure bool) (egress.Dialer, string, error) {
    tag, name, ok := strings.Cut(params, ":")
    if !ok || tag == "" || name == "" {
        return nil, "", fmt.Errorf("cbp_proxy: want <tag>:<node_id_or_label>, got %q", params)
    }

    state, err := p.table.Get(tag)
    ...
    node, err := state.Lookup(name) // ID 优先，label 兜底
    ...
    return p.dialNode(state, node, insecure)
}
```

### 9.2 CBP 连接：stream 优先，relay 可用

不要直接使用 `pkg/egress/cbp.NewCBP`。它是 raw-IP only、只直连节点，缺少 relay 和 stream fallback，遇到 NAT 后面的节点会直接失败。

新增 `pkg/cbpclient`（从 `customBrowserServer/pkg/cbpclient` 最小移植），provider 使用：

```go
client, err := cbpclient.Dial(ctx, cbpclient.Config{
    ControlAddr:   node.ControlAddr(), // host:port
    RelayAddr:     state.Coordinator.Address, // 选中主服务端 9443
    RelayNodeID:   node.ID,
    Token:         state.Config.Token, // 见 9.3
    IdentityFile:  state.IdentityPath,
    ClientID:      state.Config.Tag,
    ServerName:    node.ServerName(), // relay 时改成 state.Coordinator.ServerName
    InsecureSkipVerify: insecure,
})
```

`ServerName` 不能写死成节点 host：直连时用节点证书名，relay 时 TLS 对端是主服务端，必须用选中主服务端候选的 `ServerName`。`RelayAddr` 非空时，控制流先连主服务端 9443，由主服务端 `RELAY_OPEN` 到目标 CBP 节点；这样公网不可直连的节点也能用。直连节点可以先试 `ControlAddr`，失败再走 relay；不要只赌直连。

`cbpclient.Dial` 内部会：

1. 建立 CBP stream control session。
2. 认证 `AUTH`。
3. 尝试 QUIC raw-IP 数据通道；relay 场景下在后台 attach，失败不阻塞。
4. 保留 control-stream raw fallback。

### 9.3 token 的两个用途

这里必须明确：

- `proxy_provides.token` 在目录请求里只作为 `X-API-Key` 发送，空值不加认证头；它不参与桌面端签名，也不以 `Authorization` 发送。
- CBP 节点的 AUTH 也需要部署 token；`cbpclient.Config` 的 `Token` 为空时，会尝试从身份 bundle 的 `node.auth_token` 取。

如果主服务端的 HTTP API token 和 CBP 节点部署 token 不是同一个值，三字段配置不够用。需要二选一：

1. 约定 `proxy_provides.token` 同时是 HTTP token 和 CBP 部署 token。
2. 身份文件使用 standalone bundle，里面自带 `node.auth_token`，此时 `proxy_provides.token` 只用于 HTTP。

文档不假设两者一定相同；代码要在两者都为空时给出明确错误，而不是静默连不上。

### 9.4 返回给 egress_route

```go
type Provider interface {
    NewProxyDialer(params string, insecure bool) (Dialer, string, error)
}
```

`egress_route` 拿到后：

```go
p.dialer = d
p.proxy = proxyHost
```

`proxyHost` 用节点控制地址。`egress_route` 用它判断“这是代理出口”并给代理连接本身打排除标记；空值会导致出口被当成直连。

### 9.5 数据面

```go
conn, err := p.dialer.DialContext(ctx, "tcp", target)
conn.Write(request)
conn.Read(response)
```

`cbpDialer.DialContext` 内部：

```text
network == "tcp" -> cbpclient.OpenStream(ctx, "tcp", target)
network == "udp" -> cbpclient.OpenUDP(ctx) + connected UDP 适配
```

每个目标连接一条 CBP stream，不需要为整个出口起一个 gVisor 栈。只有显式开启 `raw_ip_data` 时，才走 `pkg/egress/cbp` 的 raw-IP 栈；默认关闭，和 CustomBrowser 桌面端默认一致。

---

## 10. 代码落点

### 10.1 根配置

`coremain/config.go`：

```go
type Config struct {
    ...
    ProxyProvides []ProxyProvideConfig `yaml:"proxy_provides"`
}

type ProxyProvideConfig struct {
    Tag          string `yaml:"tag"`
    Domain       string `yaml:"domain"`
    Token        string `yaml:"token"`
    NodeToken    string `yaml:"node_token"`
    IdentityFile string `yaml:"identity_file"`
    ConfigDat     string `yaml:"config_dat"`
    ConfigKeyFile string `yaml:"config_key_file"`
    Insecure      *bool  `yaml:"insecure"`

    GenerateDat bool `yaml:"-"` // 默认 dat 不存在，等待首次 NODE_LIST 后生成
}
```

`IdentityFile` 为空时，在 `RunMosdns` 初始化阶段填入默认值：

```go
if cfg.IdentityFile == "" {
    cfg.IdentityFile = filepath.Join(configDir, "proxy_provides", cfg.Tag+".json")
}
```

默认值必须在启动阶段就确定，不能等到第一次拨号才拼路径；否则 `check-config` 和运行期看到的配置不一致。

`config_dat` 的默认路径和存在性检查也放在同一阶段：

```go
if cfg.ConfigDat == "" {
    cfg.ConfigDat = filepath.Join(configDir, "proxy_provides", cfg.Tag+".dat")
}
if _, err := os.Stat(cfg.ConfigDat); os.IsNotExist(err) {
    cfg.GenerateDat = true
}
```

`proxyProvideBaseDir` 把相对配置目录转成绝对路径，避免 `check-config` 的工作目录和运行目录不同导致 `.dat`/身份文件写到不同位置。

`cbp_proxy` 的 `manager.refresh()` 在 `NODE_LIST` 成功、节点表落内存后调用：

```go
if s.cfg.ManageDat || s.cfg.GenerateDat {
    s.writeDatIfChanged(nodes, insecure)
}
```

写入函数为 `coremain.WriteProxyProvideDat(path, cfg, insecure, nodes)`；内存表先整体替换，再按指纹决定是否写盘。写入失败只记 `warn`，不回滚已成功的节点表和本次转发，下一轮刷新会重试。

加 `ValidateProxyProvides()`，在启动和 `check-config` 共用的加载路径里调用。

### 10.2 include 合并

`coremain/run.go` 的 `mergeInclude`：

```go
includedCfg.ProxyProvides = append(includedCfg.ProxyProvides, subCfg.ProxyProvides...)
...
cfg.ProxyProvides = append(includedCfg.ProxyProvides, cfg.ProxyProvides...)
```

### 10.3 Mosdns 注入

`coremain/mosdns.go`：

```go
type Mosdns struct {
    ...
    proxyProvides  map[string]ProxyProvideConfig
    proxyProviders map[string]egress.Provider
}
```

- `RunMosdns` 在插件初始化循环前建 `proxyProvides`。
- `addPlugin` 里类型断言 `p.(egress.Provider)`，注册到 `proxyProviders`。
- 提供 `GetProxyProvide(tag)` / `GetProxyProvider(tag)`。
- 重复 tag 启动失败。

### 10.4 egress_route

`plugin/executable/egress_route/egress_route.go` 的 `cfg.Proxy` 分支：

```go
raw := strings.TrimSpace(cfg.Proxy)

if pluginTag, params, ok := strings.Cut(raw, ":"); ok {
    if provider := bp.M().GetProxyProvider(pluginTag); provider != nil {
        d, host, err := provider.NewProxyDialer(params, cfg.ProxyInsecure)
        if err != nil {
            return nil, fmt.Errorf("egress_route: proxy provider %s: %w", pluginTag, err)
        }
        // 和内置 proxy 共用 probe、p.dialer、p.proxy 赋值
    }
}

d, err := egress.New(raw, cfg.ProxyInsecure)
```

- 命中 provider 后不回落 `egress.New`，防止配置错误静默变成别的协议。
- `p.proxy` 必须非空。
- `egress.Probe` 统一调用。
- `proxy_from` 不用改，借 `OutletDialer()` / `OutletProxyHost()`。

### 10.5 新增包

```text
pkg/egress/provider.go          // Provider 接口
pkg/cbpcoord/                   // 最小 coordinator 客户端（HELLO/AUTH/NODE_LIST）
pkg/cbpclient/                  // 从 customBrowserServer 最小移植：stream + relay + raw fallback
pkg/cbpstream/                  // 如果 cbpclient 不内嵌，则单独放 CBP stream 帧实现
plugin/executable/cbp_proxy/    // 协议插件
  cbp_proxy.go
  bootstrap.go                  // HTTPS candidates + ICMP
  table.go                      // 内存映射表、刷新
  node.go                       // 节点地址推导
  identity.go                   // 身份文件路径与申请
  cbp_proxy_test.go
```

`cbpclient` 是这次实现的主要工作量。`customBrowserServer/pkg/cbpclient` + `internal/cbpstream` 约 1.9k 行，不能直接 import `internal`，必须移植或 vendor。只做 raw-IP 的 `pkg/egress/cbp` 不能替代它，否则会丢掉 relay、stream 和 NAT 穿透。

`plugin/enabled_plugin.go` 加 blank import。

### 10.6 配置模板

`etc/mosdns/config.yaml` 的 TOP-LEVEL OPTIONS 增加 `proxy_provides` 说明，至少包含：

```yaml
# proxy_provides:
#   - tag: cbp_sg
#     domain: https://api.example.com
#     token: ""
#     # identity_file: /etc/mosdns/proxy_provides/cbp_sg.json  # 可选，默认自动生成
```

---

## 11. 安全、并发与失败策略

### 11.1 安全

- `domain` 强制 HTTPS，TLS 最低 1.2，推荐 1.3。
- `token` 不打印、不进错误信息、不写日志。
- 身份文件权限 `0600`，路径 `{config_dir}/proxy_provides/<tag>.json`。
- `insecure` 只由 `proxy_insecure` 显式打开，默认 false。
- coordinator TLS 使用 `ServerName` 校验；证书错误直接失败。
- ICMP 需要 raw socket 权限；没有权限时走 TCP 兜底，并在日志标记 `probe=tcp`。

### 11.2 并发

- 每个 tag 一把刷新锁，避免并发重复拉目录。
- 节点表读多写少，用 `RWMutex`。
- 刷新失败保留旧表；旧表为空则失败。
- 不在请求路径里做无界重试；一次刷新失败直接返回错误，由 egress_route 启动失败暴露。

### 11.3 失败策略

| 场景 | 行为 |
|---|---|
| 重复 tag | 启动失败 |
| domain 非 HTTPS | 启动失败 |
| 身份文件缺失且 token 为空、服务端要求认证 | 启动失败，提示身份申请 401 |
| 无候选 | 启动失败 |
| 所有候选 ICMP/TCP 不可达 | 启动失败 |
| 身份文件缺失且无 token | 启动失败 |
| coordinator 认证失败 | 启动失败 |
| NODE_LIST 为空 | 启动失败 |
| 节点 ID/label 不存在 | 启动失败，列出可用节点 |
| CBP 拨号失败 | 启动失败，不 direct fallback |

---

## 12. 测试计划

### 单元测试

- `proxy_provides` 解析：三字段、空 token、重复 tag、http 拒绝、非法 tag。
- `mergeInclude`：子配置在前、主配置在后。
- `egress_route` 三段式解析；内置 `socks5://...` 仍走 `egress.New`。
- HTTPS candidates：`httptest` 返回主服务端 TCP candidates；token 非空断言只有 `X-API-Key`、没有 `Authorization`，token 为空断言没有认证头；断言不出现桌面端 `X-CustomBrowser-*` 签名头。
- 两类节点隔离：`server.candidates` 不得进入 `nodeTables`；`nodeTables` 只接受 `NODE_LIST`。
- ICMP/TCP 探测：可达、不可达、ICMP 失败走 TCP、RTT 排序、main 优先。
- coordinator：HELLO/AUTH/READY/NODE_LIST 帧顺序，签名校验，错误帧。
- 节点地址推导：`PublicTCPEndpoint`、`PublicAddr + TCPEndpoint port`、LAN 兜底。
- 内存表：刷新过期、并发 singleflight、刷新失败保留旧表、nodeID 缺失。
- 身份：已有文件、无文件 + token 申请、无文件 + 空 token 报错。

### 集成测试

- 假 HTTPS candidates + 假 coordinator + 假 CBP 控制端，走完整闭环。
- `egress_route` 使用自定义 provider 出口，验证 `p.proxy` 非空、`proxy_from` 可借用。
- 刷新间隔到达后重新拉 NODE_LIST，节点表更新。

---

## 13. 与 customBrowser 对比：还缺什么

| 能力 | customBrowser 桌面端 | 当前设计 | 结论 |
|---|---|---|---|
| 身份文件 | `IdentityFile` 为空时默认 `DataDir/cbp-client-identity.json`；`ClientIDFile` 持久化稳定 ID；首次启动自动申请 | 已补 `identity_file` 可选项，默认 `{config_dir}/proxy_provides/{tag}.json`，首次自动申请 | 已补齐 |
| 客户端 ID | 硬件 UUID，失败时持久化随机 `cbdev-*` | 直接用根配置 `tag` | 可用；多 tag 天然多身份 |
| 主服务端 TCP 候选 | HTTPS `server.candidates`，ICMP + TCP 兜底，最低 RTT | 相同 | 一致，且与 CBP 节点严格分开 |
| 节点列表来源 | coordinator `NODE_LIST` | 相同 | 一致 |
| CBP 数据路径 | 默认 `cbpclient.OpenStream`，`RawIPData` 默认 false | `pkg/cbpstream` 已实现 stream，TCP 走 `OpenStream` | 已补齐 TCP；UDP 已有适配，缺真实端到端验证 |
| relay / NAT | `cbpclient` 支持 `RelayAddr` + `RelayNodeID`，主服务端 9443 转发 | `cbpstream` 支持 `RelayAddr` + `RelayNodeID`，direct 失败后回退 relay | 已补齐代码，缺真实 NAT 节点验证 |
| CBP 节点级探测 | `rankCBPNodeCandidates` 对节点地址 ICMP 排序，`dialCBP` 多节点失败重试 | 已补节点内多地址探测 + relay 回退；跨 nodeID 不切换 | 基本对齐，跨节点按要求不做 |
| 节点地址 | 同时保留 `PublicTCPEndpoint`、`TCPEndpoint`、LAN、PublicAddr | 已保留四类地址并过滤通配 endpoint | 已补齐 |
| UDP | `OpenUDP`，SOCKS5 UDP / WebRTC 可用 | `cbpstream.OpenUDP` + connected `net.Conn` 包装已落地 | 已补齐代码，缺真实端到端验证 |
| 节点刷新 | 目录 watcher + coordinator session | 5 分钟 TTL 按需刷新 | 可用，但“最新”最多滞后 5 分钟 |
| 双 token | `CBP.Token` 与 `Directory.Token` 分离 | `token` + `node_token`，后者为空回落到前者 | 已补齐 |
| 区域过滤 | 身份带 `Regions`，节点列表按区域过滤 | 没有 regions 字段 | 默认全区域；需要时再加 |
| 静态节点兜底 | 目录失败回退 `Network.CBP.Nodes` | 没有静态兜底 | 按当前“实时节点”目标，可以不做 |

### 13.1 本地实现后的剩余缺口

1. **双 token 已拆开，内置 host 的初始 token 已内置。** `token` 用于 HTTPS API，`node_token` 用于 CBP 节点 `AUTH`，空时回落到 `token`；身份文件里的 `client_id` 优先于根配置 `tag`。
2. **可通过 `config_dat` 读取桌面 proto .dat。** `coremain/proxy_provide_dat.go` 按 `config.proto/v1` 解析 `ConfigDocument -> Config.network -> CBPConfig`，读取 `identity_server_url`、`identity_token`、`token`、`identity_file`、`insecure_skip_verify`；portable `CBCFG1`、裸 proto 和带 `config_key_file` 的 runtime `CBCFG2` 均可用。
3. **内置初始凭据已写死在代码里。** `api.aa2.dev` / `api.aa3.dev` 的 bootstrap 与节点 AUTH 凭据放在 `coremain/proxy_provide_defaults.go`，客户端身份仍由服务端签发并保存到 `identity_file`；其他域名不继承这套凭据。
4. **真实环境只做了单机初步验证。** 已用 customBrowser 现有客户端身份、控制面 token 与节点 token 跑通 `https://api.aa2.dev`：拿到 2 个节点，最低 RTT 主服务端为 `103.49.60.205:9443`；节点 `edge-vyos-1` 直连 `8443` TLS EOF，relay 成功；TCP `example.com:80` 返回 `HTTP/1.1 200 OK`，UDP `8.8.8.8:53` 返回 DNS 报文。尚未验证长时间稳定性、线上路由器部署和不同节点。
5. **跨节点 failover 不做。** 用户指定 `nodeID` 后，只在该节点的多个地址内探测和 relay 回退，不会自动换到另一个节点。

### 13.2 已经对齐、不用补的

- HTTPS 取 `server.candidates`，不是直接取 CBP 节点。
- ICMP 优先、TCP 兜底、最低 RTT。
- coordinator `HELLO -> CLIENT_AUTH -> CLIENT_READY -> NODE_LIST`。
- 节点列表进内存，不落盘。
- 非内置 host 的 `token` 为空时 HTTP 不加 `Authorization`；内置 host 使用代码里的初始凭据。

## 14. 实施顺序

1. `pkg/egress/provider.go` 加接口。
2. `coremain/config.go` 加 `proxy_provides` 和校验。
3. `coremain/run.go` 的 `mergeInclude` 合并。
4. `coremain/mosdns.go` 注入配置、注册 provider、加访问器。
5. `egress_route` 加自定义 provider 分支。
6. `pkg/cbpcoord` 实现最小 coordinator 客户端。
7. `pkg/cbpclient` 移植 stream + relay + raw fallback；先跑通 `OpenStream`，再补 `OpenUDP`。
8. `plugin/executable/cbp_proxy` 实现 HTTPS candidates、ICMP、节点表、CBP 拨号。
9. `plugin/enabled_plugin.go` 注册。
10. `etc/mosdns/config.yaml` 模板和文档。
11. 测试、发布。

---

## 15. 待确认

1. `proxy_provides` 是最终字段名，还是 `proxy_providers`。
2. `proxy_provides.token` 是否同时作为 CBP 节点部署 token；如果只用于 HTTP，CBP token 需要从身份 bundle 取。
3. `identity_file` 的默认路径是否可接受；首次启动自动申请、已有文件直接加载的规则是否确认。
4. coordinator 是“取一次 NODE_LIST 后关闭”，还是保持长连接接收后续更新。当前设计按 5 分钟 TTL 重新拉取，简单且闭环。
5. `nodeID` 缺失时是否允许回退到第一个节点；建议不允许，配置错误应启动失败。

---

## 16. 本地实现状态

本轮只做本地实现与本地测试，未部署到线上路由器。

已落地：

- `pkg/egress/provider.go`：`Provider` 接口与 `ProviderFunc`。
- `coremain/proxy_provides.go`：`proxy_provides` 默认值、HTTPS 校验、重复 tag 校验、身份文件默认路径。
- `coremain/config.go` / `checkconfig.go` / `mosdns.go` / `run.go`：根配置加载、include 合并、provider 注册与访问器。
- `plugin/executable/egress_route/egress_route.go`：第一个冒号命中自定义 provider 时，把剩余参数原样交给 provider，不再回落到内置 scheme。
- `pkg/cbp`：CBP control/stream 协议结构、BufferedConn、UDP frame。
- `pkg/cbpstream`：stream 会话、TCP `OpenStream`、UDP `OpenUDP`、relay preamble。
- `pkg/cbpidentity`：客户端 Ed25519 身份加载/首次申请。
- `pkg/cbpcoord`：主服务端 TCP coordinator 的 `HELLO -> CLIENT_AUTH -> CLIENT_READY -> NODE_LIST`。
- `plugin/executable/cbp_proxy`：HTTPS candidates、ICMP/TCP 选主服务端、节点表 TTL、节点地址推导、direct/relay 拨号、TCP/UDP dialer。
- `plugin/enabled_plugin.go`：注册 `cbp_proxy`。
- `etc/mosdns/config.yaml`：`proxy_provides` 模板说明。

本地测试覆盖：

- 根配置解析、HTTPS 拒绝、重复 tag、身份文件默认路径。
- Bootstrap API Key 头：非空只发送 `X-API-Key`，不发送 `Authorization`；空 token 不发送认证头；不发送桌面端签名头。
- 两类节点隔离：bootstrap candidates 不进入节点表。
- coordinator 握手与 `NODE_LIST`。
- CBP stream 的 `STREAM_OPEN` / `STREAM_DATA` 往返。
- fake HTTPS + fake coordinator + fake CBP node 的完整闭环，出口 `DialContext` 能写入并读回数据。
- `go test ./...` 全量通过。
- 真实 `api.aa2.dev` 冒烟：Bootstrap、ICMP 选主服务端、`NODE_LIST`、节点 direct→relay、TCP HTTP、UDP DNS 均有结果。
- 真实桌面 proto `.dat` 冒烟：CustomBrowser 导出的 `CBCFG1` 和实际 runtime `config.dat`（`CBCFG2` + `config_key_file`）都通过 `config_dat` 读取，未写 YAML token / domain / insecure，节点列表和 relay 链路正常。
- 默认 `.dat` 自动生成冒烟：只写 `tag` 和 `domain: https://api.aa2.dev`，启动时 `GenerateDat=true`、`ManageDat=true`；首次 `NODE_LIST` 后生成 `{config_dir}/proxy_provides/{tag}.dat`，权限 `0600`，TCP `example.com:80` 返回 `HTTP/1.1 200 OK`；重启后 `GenerateDat=false`、`ManageDat=true`，从 `.dat` 读回 domain/token/identity，节点表为 2。
- `.dat` 同步单测：同一节点表指纹不重写；节点 ID 变化后重写。`.dat` 的 `nodes` 与内存表一样整体替换，不保留旧 ID。
- 生成文件用桌面 `custombrowser/internal/config.LoadBuiltinDat` 解码验证通过：`network.cbp.enabled=true`，`control_addr`、`identity_file`、`identity_server_url`、`nodes`（`control/public/lan` 均为 host:port）、`insecure_skip_verify` 均符合桌面 schema。

未完成/待接真实环境验证：

- 真实主服务端证书、token、identity 文件签发。
- 真实 CBP 节点 relay/NAT 场景。
- ~~`proxy_provides.token` 与 CBP 节点部署 token 不一致时的双 token 方案~~ 已用 `node_token` 补齐。
- 运行期节点表后台预热；当前按需刷新，TTL 5 分钟。

---

## 17. 控制会话生命周期：保活与重连（2026-11-23）

线上节点 `edge-vyos-sg1` 的 `SESSION_READY.expires_at` 实测为 5 分钟，服务端 `runControl()` 每次读控制帧都把读超时设为 `SessionTTL`，超时无控制帧就关闭会话。mosdns 的 egress 在无流量时会静默，旧实现没有周期心跳，也没有会话失效后的重拨，于是约 5 分钟后所有流都返回 `cbpstream: client closed`。

客户端与服务端的对齐规则：

1. `pkg/cbpstream.Client` 在 `Dial` 成功后启动 20 秒周期心跳，发送 `PING`（ID `^uint64(0)`，避开 `PingProxy` 的 1..N 序列和旧节点的空 PONG 兼容分支）。服务端收到任意控制帧都会 `touch()` 并顺延 `expires_at`，因此心跳同时保活控制会话，不需要额外协议。
2. `cbpDialer` 在每次 `DialContext` / `Probe` 前检查 `Healthy()`；会话已关闭时用同一份 `cbpstream.Config` 重新执行 TLS + AUTH，等价于桌面端 `pkg/cbpclient.Ensure`。
3. `OpenStream` / `OpenUDP` 返回 `client closed` 时，丢弃旧 client，重拨一次后重试；非 `client closed` 错误不重试，避免掩盖节点出口错误。
4. `cbpDialer.Close()` 置 closed 标记，之后不再自动重连，避免插件退出后残留会话。

本地验证：

- 使用线上同一身份文件和节点 token，经主服务端 relay 连接 `edge-vyos-sg1`，`SESSION_READY.expires_at` 为 5 分钟。
- 保持 5 分 30 秒后 `Healthy()==true` 且能成功 `OpenStream`；证明 20 秒 PING 已把服务端会话延续超过原始 5 分钟 TTL。

---

## 18. 与服务端 2026-11-23 最新改动的对齐

服务端最新源码已经把控制面能力扩展为：16 KiB 优先流分片、`RESOLVE` / `RAW_OPEN` / `RAW_PACKET`、relay 的 `RELAY_OPENED.stream_protocol`、节点侧的会话/流槽共享池、节点到中心的流量上报和 `NODE_REMOVED`、中心到节点的 `RELAY_HINT`/`RELAY_ACK`。

mosdns 客户端的对齐结果：

1. **流分片**：`pkg/cbp` 的 `PreferredStreamChunk=16 KiB` 与服务端一致；写 TCP/UDP 时均按该值切片。
2. **控制消息**：`RESOLVE_RESULT`、`RAW_READY`、`RAW_PACKET` 已处理；`PONG` 按 payload 中的 ID 匹配，保活 PING 使用 `^uint64(0)`，不会误取 `PingProxy` 的在途结果。
3. **relay 协议**：`RELAY_OPENED` 读取 `stream_protocol`，决定节点内层是 binary credit 还是 legacy JSON；`RELAY_HINT`/`RELAY_ACK` 是主服务端和节点之间的准入握手，客户端不发送也不解析。
4. **会话/流槽池**：服务端在池满时会把 `SESSION_READY` 或 `STREAM_ACK` 排队最长 5 分钟。客户端 `Dial` 的控制握手增加了 `DialTimeout`/调用方 deadline，避免被服务端排队无限挂住；`OpenStream`/`OpenUDP` 在调用方取消时发送 `STREAM_CLOSE`，不再留下已放弃的待开流。
5. **认证口径**：节点 `AUTH` 仍是节点 token + Ed25519 签名 + `device_id`；`client_id` 只用于主服务端/relay。节点如果启用 `RequireClientKeys`，公钥白名单就是设备身份，`auth_token` 只作为共享部署门禁。
6. **流量与节点移除**：`TRAFFIC_REPORT`/`TRAFFIC_ACK`、`NODE_REMOVED` 只在节点与主服务端之间；mosdns 的 `pkg/cbpcoord` 只取一次 `NODE_LIST` 后关闭，不持有节点注册会话，因此无需实现。

本地验证：用线上同一身份经 relay 完成 `AUTH`、`OpenStream(1.1.1.1:80)` 和 `OpenUDP` DNS 查询，均成功。

---

## 19. 启动顺序与 bootstrap DNS

`proxy_provides` 的 `refresh()` 在 egress_route 初始化阶段就要访问 `https://{domain}/v1/edge/bootstrap`，而 mosdns 的 DNS 监听此时还没有开始。若 `/etc/resolv.conf` 指向 `127.0.0.1`，服务冷启动/重启会形成循环依赖：bootstrap 需要 DNS，但 DNS 服务还没起来。

线上 VyOS 的处理：在 `/etc/hosts` 固定 `api.aa2.dev` 的当前 A 记录，让冷启动的 bootstrap 请求不经过本机 53。该条目只用于 bootstrap，后续 NODE_LIST 刷新仍走正常网络。若域名 A 记录变更或迁移到非 Cloudflare 地址，需要同步更新 `/etc/hosts`；长期方案是给 provider 增加独立的 bootstrap resolver 或从 `.dat` 恢复节点表，避免启动依赖本机 DNS。
