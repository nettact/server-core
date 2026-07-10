# server-core

NetTact 服务端**核心模块库**（模块化单体，架构 §6/§15.4）。被 server-lite 组合使用，未来官方 Cloud 也复用同一核心（不复制代码，§15.3）。Apache-2.0 / 双重授权。

M1 模块：
- `store/` — SQLite（`modernc.org/sqlite` 纯 Go）+ 内嵌迁移。
- `ingest/` — 遥测接入，按 `(agent_id, sequence)` 幂等去重。
- `registry/` `site/` — Agent 与 Site。
- `api/` — chi 路由 + handler（Cloud 可复用）。
- `eventbus/` — 进程内事件总线。

后续里程碑加入 identity / rules / alert / incident / notification / config / audit。

依赖 [github.com/nettact/protocol](https://github.com/nettact/protocol)。本地多仓开发使用 `go.work`。
