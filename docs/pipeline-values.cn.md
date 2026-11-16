# 流水线取值契约（pkg/pipeline + pkg/routepolicy）

## 为什么需要这一层

fakeip_nat、asn_tun、alias 三个插件在同一份配置里同时运行，各自决定"哪些目的地归我、送进哪张表、走哪个下一跳"。拆分共享实现后，出现两个具体的歧义：

1. **请求级歧义**：`query_context.Context` 原先只有一组 `marks map[uint]struct{}`，任何插件都能往上加标记，事后没有任何信息说明这个标记是谁加的、代表什么。两个插件都做过路由决定时，读者无法分辨手上的是谁的。
2. **进程级歧义**：两个插件如果写了同一个 fwmark，或同一张表的同一个优先级，内核会把两条规则都装上，后装的那条只是永远匹配不到。运行期看不出冲突，也看不出该删谁。

这一层只解决"值能不能被准确归属"，不改变任何插件自己的判断逻辑。

## 请求级：pkg/pipeline

- **Key 是类型化的槽位**。`pipeline.NewKey[T](name)` 返回 `*Key[T]`，存取的键是「槽位指针身份 + Owner」。同名不同槽不会串，同类型不同槽也不会串；读错类型返回 not-found，而不是把别的值解释成当前类型。
- **Owner 就是插件 tag**。`pipeline.Owner(p.Tag())`。值与其来源永远绑在一起，日志里出现的决定必然能追到插件。
- **同一 Owner 重写即替换**，符合一个插件在同一条链路里重试/改判的场景。
- **Snapshot 用来写日志/核对**：`Snapshot(ctx, key)` 返回 `map[Owner]T`，两个插件都做了决定时都能列出来，而不是最后一次写入悄悄胜出。
- **Copy 语义是快照**：`Context.Copy()` 会复制值的映射（浅拷贝），分支能看到 fork 之前已做的决定，分支自己的写入不会回灌父上下文。
- **值入库后按只读对待**：结构体按值存储，指针型值共享；需要修改请重新 Set，不要就地改。

存储实现在 `query_context.Context` 上：`SetValue/Value/DeleteValue/Values` 用 `any` 做键，本包在其上建立类型与归属，不让上下文退化成字符串字典。

## 路由决定的载体：routepolicy.Decision

一次路由决定所需的字段必须成套出现，拆开就无法落到内核，因此放在一个结构里：

| 字段 | 含义 |
| --- | --- |
| `Mark` | 选择表的 fwmark；0 表示用源地址规则而非 mark |
| `NFTable` | 施加 mark 的 nft 表名（需要时） |
| `Table` | 被选中的路由表 |
| `Priority` | 指向该表的 `ip rule` 优先级 |
| `NextHop` / `Dev` | 该表把流量送去哪里 |
| `Source` | 需要固定源地址时使用 |

- `SetDecision(ctx, owner, d)` / `DecisionFor(ctx, owner)` / `Decisions(ctx)`。
- `Decision.String()` 是日志形态，字段全列且区分"无 mark""仅设备"，目的是让两条决定在日志里一眼可分。

## 进程级：routepolicy.Registry

- 唯一性键：有 mark 时按 `mark`，否则按 `table + priority`（源地址规则形态）。
- 同一 Owner 重复 claim 视为幂等（插件重启会重装同一对象）。
- 不同 Owner 抢同一对象 → 返回错误，错误里同时点名持有的插件与试图接管的插件。
- 插件在安装内核对象处 claim，在清理处 `Release(tag)`，避免同进程内重启留下过期归属。

已接入：`fakeip_nat`（`setupMarkRouting` claim / `cleanupMarkRouting` release）、`asn_tun`（`installRoutes` 安装 ingress 后 claim）、`alias`（`installOutletRoute` 安装 outlet 路由后 claim）。冲突当前记录为 Error 日志而不中断启动，避免一台在跑的解析器因为配置冲突直接起不来；日志中可以直接看到两个插件名。

## 后续（Phase 1 起）

`pkg/routepolicy` 的安装器将直接消费 `Decision`：先 claim，再落内核对象，清理时按 claim 反推要删什么。届时三个插件只提供"谁的地盘"与"决定值"，不再各自拼 `ip rule` / `ip route` / `nft` 命令。
