package ingest

import (
	"context"
	"testing"
	"time"

	"github.com/nettact/protocol"
	"github.com/nettact/protocol/gamesense"
	"github.com/nettact/protocol/telemetry"
	"github.com/nettact/server-core/metrics"
	"github.com/nettact/server-core/store"
	"github.com/nettact/server-core/store/storetest"
	"github.com/nettact/server-core/tsstore/tsstoretest"
)

func openGameIngest(t *testing.T) (*store.DB, *Service) {
	t.Helper()
	db := storetest.Open(t)
	ctx := context.Background()
	if _, err := db.ExecContext(ctx,
		`INSERT INTO sites(id,name,created_at) VALUES('site_default','Default',?)`, time.Now().UTC()); err != nil {
		t.Fatalf("seed site: %v", err)
	}
	if _, err := db.ExecContext(ctx,
		`INSERT INTO agents(id,site_id,public_key,token_hash,status,perm_effective)
		 VALUES('agent_game','site_default',x'00','h','online','["game.process.detect","game.performance.read"]')`); err != nil {
		t.Fatalf("seed agent: %v", err)
	}
	return db, New(db, nil, metrics.New(db, tsstoretest.Open(t)), nil, nil, nil)
}

// gamePacket carries one run and two of its seconds, addressed by sequence.
func gamePacket(seq uint64, start time.Time) telemetry.Packet {
	counts := make([]uint32, gamesense.HistBins)
	bin, _ := gamesense.HistBucket(5)
	counts[bin] = 100
	sample := gamesense.Sample{
		Frames: gamesense.Frames{Presented: 100},
		FT:     gamesense.FrameTimes{Avg: 5.77, P50: 5.7, P95: 6.1, P99: 6.4, Max: 7, SD: 0.3},
		Hist:   gamesense.Histogram{Layout: gamesense.HistLayoutLog24V1, Counts: counts},
	}
	return telemetry.Packet{
		SchemaVersion: protocol.SchemaVersion, AgentID: "agent_game", SiteID: "site_default",
		Sequence: seq, SentAt: start,
		GameRuns: []gamesense.Run{{
			ID: "run_1", Proc: "game.exe", Title: "A Game",
			StartedAt: start, LastSeenAt: start.Add(2 * time.Second),
			Source: gamesense.SourcePresentMonService,
			Caps:   []string{gamesense.CapDisplayed},
		}},
		GameBuckets: []gamesense.Bucket{
			{RunID: "run_1", TS: start, Sample: sample},
			{RunID: "run_1", TS: start.Add(time.Second), Sample: sample},
		},
	}
}

// TestGameDataIngestIsIdempotent covers the wiring rather than the storage: a
// retried upload arrives under a NEW sequence (the packet-level dedup does not
// catch it), so the run and its seconds must be idempotent in their own right or
// every reconnect would double a session's frame counts.
func TestGameDataIngestIsIdempotent(t *testing.T) {
	db, svc := openGameIngest(t)
	ctx := context.Background()
	start := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)

	if _, err := svc.Ingest(ctx, "agent_game", "site_default", gamePacket(1, start)); err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if _, err := svc.Ingest(ctx, "agent_game", "site_default", gamePacket(2, start)); err != nil {
		t.Fatalf("re-ingest under a new sequence: %v", err)
	}

	var runs, buckets int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM game_runs`).Scan(&runs); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM game_buckets`).Scan(&buckets); err != nil {
		t.Fatal(err)
	}
	if runs != 1 || buckets != 2 {
		t.Fatalf("after a retried upload: runs=%d buckets=%d, want 1 and 2", runs, buckets)
	}

	var presented int
	if err := db.QueryRowContext(ctx,
		`SELECT SUM(presented) FROM game_buckets WHERE run_id='run_1'`).Scan(&presented); err != nil {
		t.Fatal(err)
	}
	if presented != 200 {
		t.Fatalf("presented total = %d, want 200 (the retry must not add frames)", presented)
	}
}

// TestGameDataDroppedWithoutPermission: an agent whose policy does not grant
// game.performance.read has its frame data refused at ingest, even though the
// rest of the packet is accepted.
func TestGameDataDroppedWithoutPermission(t *testing.T) {
	db, svc := openGameIngest(t)
	ctx := context.Background()
	if _, err := db.ExecContext(ctx,
		`INSERT INTO agents(id,site_id,public_key,token_hash,status,perm_effective)
		 VALUES('agent_plain','site_default',x'00','h','online','["host.cpu.read"]')`); err != nil {
		t.Fatalf("seed agent: %v", err)
	}
	start := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	pkt := gamePacket(1, start)
	pkt.AgentID = "agent_plain"

	ack, err := svc.Ingest(ctx, "agent_plain", "site_default", pkt)
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if ack.HighestSequence != 1 {
		t.Fatalf("ack = %+v, want the packet acknowledged despite the dropped game data", ack)
	}
	var runs int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM game_runs`).Scan(&runs); err != nil {
		t.Fatal(err)
	}
	if runs != 0 {
		t.Fatalf("game_runs = %d rows for an agent without the permission", runs)
	}
}
