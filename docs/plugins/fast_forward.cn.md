[English](fast_forward.md) | 简体中文

# fast_forward — 并行取最快
- **文件**：`plugin/executable/fast_forward/fast_forward.go`（`udpme.go` 为定制协议）
- **注册**：`:43`；**参数**（`:56-75`）：`upstream[]{addr, dial_addr, trusted, socks5, so_mark, bind_to_device, idle_timeout, max_conns, enable_pipeline, enable_http3, bootstrap, insecure_skip_verify}`、`ca[]`
- **行为**：构造时把**第一个上游强制设为 trusted**（`:145-147`）；`Exec` → `bundled_upstream.ExchangeParallel`（`:187`），谁先回包用谁
- **定制点**：`addr` 以 `udpme://` 开头时走内置 `udpmeUpstream`（`:106-113`），仅此插件支持
