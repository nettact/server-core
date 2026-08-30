module github.com/nettact/server-core

go 1.25

// Do NOT run `go mod tidy` here. This module is only ever built inside the
// workspace (the root go.work locally, `go work init` in the release
// workflows), which is also what resolves the versionless nettact/protocol
// require above — tidy cannot resolve it and, given the chance, rewrites this
// file with ~90 transitive indirect requires from the Prometheus TSDB graph
// (AWS/Azure/GCP/k8s discovery) and quietly upgrades golang.org/x/crypto and
// x/sys. Requires are added by hand; workspace mode writes the hashes into the
// workspace's go.work.sum, so the absence of Prometheus entries in this
// module's go.sum is expected and does not break a `-mod=readonly` build.
require (
	github.com/coder/websocket v1.8.14
	github.com/go-chi/chi/v5 v5.2.1
	github.com/google/uuid v1.6.0
	github.com/nettact/protocol v0.0.0-00010101000000-000000000000
	github.com/prometheus/client_golang v1.23.2
	github.com/prometheus/prometheus v0.313.2
	golang.org/x/crypto v0.34.0
	golang.org/x/sys v0.47.0
	google.golang.org/protobuf v1.36.11
	modernc.org/sqlite v1.57.0
)

require (
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	modernc.org/fileutil v1.4.0 // indirect
	modernc.org/libc v1.74.4 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
)
