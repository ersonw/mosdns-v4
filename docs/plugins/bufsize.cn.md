[English](bufsize.md) | 简体中文

# bufsize
- **文件**：`plugin/executable/bufsize/bufsize.go`；注册 `:32`；参数 `size`（512–4096，超出即夹紧，`:46-54`）
- **行为**：只收窄查询里的 `UDPSize`（`:56-66`）
