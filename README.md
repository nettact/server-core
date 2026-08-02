# NetTact Server Core

English | [简体中文](./README-zh.md)

NetTact Server Core is the reusable Go module behind the NetTact server. It receives Agent data, stores metrics and configuration, detects faults, organizes incidents and notifications, and exposes the HTTP API and live updates consumed by the web console.

This repository is a library and does not contain a standalone `main` program. End users should follow the [deployment guide](https://nettact.org/en/deploy) to install NetTact Lite, or use [NetTact Desktop](https://nettact.org/en/desktop) for an all-in-one local experience. Both products use this repository and therefore provide the same core server behavior.

## Capabilities

- Agent enrollment, authentication, connectivity state, and persistent WebSocket sessions
- Ingestion of ICMP, DNS, HTTP, TCP, NAT, host, Wi-Fi, and game data
- SQLite storage, WAL, separate read/write pools, embedded migrations, rollups, and retention
- Sites, Agent groups, monitor groups, targets, and egress-proxy configuration
- Target status, availability, fault signals, fluctuations, and incident lifecycle
- Incident snapshots, traceroute reports, and diagnostic-evidence orchestration
- Notification policies, channels, templates, and delivery history
- Single-user sessions, management APIs, SSE live updates, and optional web-console hosting
- Historical-data cleanup, operational issues, auditing, and update checks

## Why the Core Is a Library

- **Consistent behavior**: the self-hosted Server and Desktop do not implement separate alerting, storage, or API stacks.
- **Embeddable**: host products can choose their listener, TLS, frontend resources, version policy, and process lifecycle.
- **Simple runtime**: the default pure-Go SQLite driver requires neither an external database nor CGO.
- **Read/write isolation**: one SQLite writer and a separate read pool prevent dashboard queries from blocking telemetry ingestion.
- **Clear module boundaries**: storage, enrollment, configuration, metrics, faults, notifications, and APIs can be tested and composed independently.

## Deployment

Server Core is not a deployable unit. See the [NetTact deployment guide](https://nettact.org/en/deploy) for Docker Compose, standalone hosting, first login, Agent enrollment, upgrades, backups, HTTPS, and troubleshooting. See [Server configuration](https://nettact.org/en/server-config) for server flags, retention, and session settings.

This README documents the library and its integration surface; deployment commands and runtime configuration are intentionally maintained only in the user documentation.

## Using It in a Go Project

```bash
go get github.com/nettact/server-core@latest
```

Packages can be composed independently. For example, opening the database creates the file when needed and applies embedded migrations:

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

A complete server must wire together enrollment, metrics, configuration, the Agent WebSocket, faults, notifications, background workers, and `api.Router`. These components have lifecycle and dependency ordering requirements. Use [server-lite's `liteserver`](https://github.com/nettact/server-lite/tree/main/liteserver) as the reference assembly instead of copying wiring into an empty HTTP server.

Main packages:

| Package | Purpose |
|---|---|
| `store`, `metrics`, `gamedata` | Database, time-series metrics, and game data |
| `registry`, `agentws`, `ingest` | Agent enrollment, connections, and ingestion |
| `config`, `site`, `inventory` | Monitoring configuration, sites, and inventory |
| `fault`, `incident`, `incidentops` | Fault detection, incidents, and diagnostic orchestration |
| `notification`, `notifypolicy` | Notification channels, templates, and delivery policy |
| `targetstatus`, `agentstatus` | Current target and Agent status aggregation |
| `api`, `sse` | HTTP APIs, session authentication, and live event streams |
| `cleanup`, `settings`, `audit` | Data governance, server settings, and auditing |

## Data and Security Boundaries

- Data is stored in the SQLite file chosen by the host. A deployment must back up the database together with its WAL/SHM files, or stop gracefully before copying it.
- Agents use signed enrollment and persistent credentials; console APIs use an HttpOnly session cookie.
- Production hosts should serve native TLS or sit behind a trusted TLS-terminating reverse proxy with Secure cookies enabled.
- `api.Router` provides application routes only. The host program owns listeners, TLS, signals, database paths, and the web UI lifecycle.

## Local Development

The project requires Go 1.25 and the sibling `protocol` module in the same workspace:

```bash
go test ./...
go build ./...
```

The root `go.work` resolves local dependencies during multi-repository development. To run the complete product, start `nettact-lite` from `server-lite` rather than trying to execute this repository directly.

## License

[Apache License 2.0](./LICENSE)
