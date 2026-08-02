# NetTact Server Core

[English](./README.md) | 简体中文

NetTact Server Core 是 NetTact 服务端的核心 Go 模块。它负责接收 Agent 数据、保存指标与配置、判断故障、组织事件和通知，并向 Web 控制台提供 HTTP API 与实时更新。

这个仓库是可复用的服务端库，不包含独立的 `main` 程序。希望直接使用 NetTact 的用户应按照[部署文档](https://nettact.org/zh/deploy)安装 NetTact Lite；希望免部署体验的个人用户可使用 [NetTact Desktop](https://nettact.org/zh/desktop)。两者都基于本仓库提供相同的服务端能力。

## 提供的能力

- Agent 注册、身份验证、在线状态与持久 WebSocket 会话
- ICMP、DNS、HTTP、TCP、NAT、主机、Wi-Fi 和游戏数据接收
- SQLite 存储、WAL、读写连接池、自动迁移、汇总与保留策略
- 站点、Agent 分组、监控分组、目标和代理出口配置
- 目标状态、可用率、故障信号、波动记录和事件生命周期
- 故障现场快照、路径追踪和诊断证据编排
- 通知策略、通知渠道、模板和发送记录
- 单用户会话、管理 API、SSE 实时更新和可选 Web 控制台托管
- 历史数据清理、运行问题提示、审计和更新检查

## 为什么把核心能力做成库

- **同一套行为**：自托管 Server 和 Desktop 不会各自实现一套告警、存储或 API。
- **容易嵌入**：上层产品可以选择监听方式、TLS、前端资源、版本策略和生命周期管理。
- **部署简单**：默认使用纯 Go SQLite 驱动，不要求外部数据库或 CGO。
- **读写隔离**：SQLite 单写入连接配合独立只读连接池，控制台查询不会阻塞遥测写入。
- **模块边界清晰**：存储、注册、配置、指标、故障、通知和 API 可以分别测试与替换。

## 部署

Server Core 不是独立部署单元。Docker Compose、自托管二进制、首次登录、Agent 接入、升级、备份、HTTPS 和排障统一参见 [NetTact 部署文档](https://nettact.org/zh/deploy)；Server 参数、数据保留和会话设置参见 [Server 配置文档](https://nettact.org/zh/server-config)。

README 只说明库的定位和集成方式，不重复维护部署命令与运行参数。

## 在 Go 项目中使用

```bash
go get github.com/nettact/server-core@latest
```

各包可以独立组合。例如，打开数据库时会创建所需文件并执行内置迁移：

```go
package main

import (
    "log"

    "github.com/nettact/server-core/settings"
    "github.com/nettact/server-core/store"
)

func main() {
    db, err := store.Open("./nettact.db")
    if err != nil {
        log.Fatal(err)
    }
    defer db.Close()

    settingsService := settings.New(db)
    _ = settingsService
}
```

完整服务需要组合注册、指标、配置、Agent WebSocket、故障、通知、后台任务和 `api.Router`。这些组件存在生命周期和依赖顺序，建议参考 [server-lite 的 `liteserver`](https://github.com/nettact/server-lite/tree/main/liteserver) 作为标准装配方式，而不是从一个空的 HTTP Server 开始复制接线代码。

主要包：

| 包 | 用途 |
|---|---|
| `store`, `metrics`, `gamedata` | 数据库、时序指标和游戏数据 |
| `registry`, `agentws`, `ingest` | Agent 注册、连接与数据接收 |
| `config`, `site`, `inventory` | 监控配置、站点和设备清单 |
| `fault`, `incident`, `incidentops` | 故障判断、事件和诊断编排 |
| `notification`, `notifypolicy` | 通知渠道、模板与发送策略 |
| `targetstatus`, `agentstatus` | 目标与 Agent 当前状态聚合 |
| `api`, `sse` | HTTP API、会话鉴权和实时事件流 |
| `cleanup`, `settings`, `audit` | 数据治理、服务设置和审计 |

## 数据与安全边界

- 数据默认保存在调用方指定的 SQLite 文件中；部署时应同时备份数据库及其 WAL/SHM 文件，或先优雅停止服务再复制。
- Agent 使用签名注册与持久凭据，控制台 API 使用 HttpOnly 会话 Cookie。
- 生产环境应使用原生 TLS，或放在可靠的 TLS 终止反向代理后，并启用 Secure Cookie。
- `api.Router` 只提供应用路由；监听地址、TLS、进程信号、数据库路径和 Web UI 生命周期由宿主程序负责。

## 本地开发

本项目使用 Go 1.25，并依赖同一工作区中的 `protocol`：

```bash
go test ./...
go build ./...
```

NetTact 多仓开发时由根目录 `go.work` 解析本地依赖。要运行完整产品，请在 `server-lite` 中启动 `nettact-lite`，而不是直接运行本仓库。

## 许可证

[Apache License 2.0](./LICENSE)
