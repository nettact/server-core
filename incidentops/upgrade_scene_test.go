package incidentops

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nettact/protocol/telemetry"
	"github.com/nettact/server-core/settings"
	"github.com/nettact/server-core/store"
	"github.com/nettact/server-core/store/storetest"
)

// The end-to-end form of the store's baseline-drift regression, through the
// real scene path. A database created by a release whose 0001_init.sql
// predated the scene tables, then upgraded by a build without the baseline
// repair, has version 1 and 2 recorded and no scene_reports table: Recover
// fails at startup and every packet carrying a scene fails ingest, so the
// agent's session is torn down and its backlog never drains. Opened through
// store.Open by this build, the same file must recover and ingest normally.
//
// The released 0001 texts are the store package's fixtures, read in place so
// there is one copy of the evidence.
func TestSceneIngestWorksAfterUpgradeFromEveryReleasedBaseline(t *testing.T) {
	dir := filepath.Join("..", "store", "testdata", "released_0001")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read fixtures: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("no released baseline fixtures")
	}
	schema8, err := os.ReadFile(filepath.Join("..", "store", "migrations", "0002_schema8_epoch.sql"))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		baseline, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		hadScenes := strings.Contains(string(baseline), "CREATE TABLE scene_reports")
		t.Run(strings.TrimSuffix(e.Name(), ".sql"), func(t *testing.T) {
			ctx := context.Background()
			path := filepath.Join(storetest.Dir(t), "released.db")
			raw, err := sql.Open("sqlite", path+"?_pragma=foreign_keys(ON)")
			if err != nil {
				t.Fatal(err)
			}
			// More than one: the service reads through its handle while the
			// ingest transaction holds a connection, as the real read pool allows.
			raw.SetMaxOpenConns(4)
			for _, q := range []string{
				`CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY, applied_at TIMESTAMP NOT NULL)`,
				string(baseline),
				`INSERT INTO schema_migrations(version, applied_at) VALUES(1, CURRENT_TIMESTAMP)`,
				string(schema8),
				`INSERT INTO schema_migrations(version, applied_at) VALUES(2, CURRENT_TIMESTAMP)`,
				`INSERT INTO sites(id,name) VALUES('site_default','Home')`,
				`INSERT INTO agents(id,site_id,public_key,token_hash,status) VALUES('agent_a','site_default',x'00','h','online')`,
			} {
				if _, err := raw.ExecContext(ctx, q); err != nil {
					raw.Close()
					t.Fatalf("build released database: %v", err)
				}
			}
			now := time.Now().UTC()

			// Before: the database exactly as a build without the repair runs it.
			if !hadScenes {
				old := &store.DB{DB: raw}
				svc := New(old, nil, settings.New(old), nil)
				if err := svc.Recover(ctx); err == nil || !strings.Contains(err.Error(), "scene_reports") {
					t.Errorf("Recover on the unrepaired database = %v, want the missing scene_reports table", err)
				}
				tx, err := raw.BeginTx(ctx, nil)
				if err != nil {
					t.Fatal(err)
				}
				_, err = svc.IngestScenesTx(ctx, store.AdaptTx(tx, store.Standalone()), "agent_a", "site_default",
					[]telemetry.SceneReport{basicScene("scene_before", now, probeTrigger("probe_x", 1, now))})
				tx.Rollback()
				if err == nil || !strings.Contains(err.Error(), "scene_reports") {
					t.Errorf("scene ingest on the unrepaired database = %v, want the missing scene_reports table", err)
				}
			}
			if err := raw.Close(); err != nil {
				t.Fatal(err)
			}

			// After: the normal open path repairs the drift.
			db, err := store.Open(path)
			if err != nil {
				t.Fatalf("store.Open: %v", err)
			}
			t.Cleanup(func() { db.Close() })
			svc := New(db, nil, settings.New(db), nil)
			if err := svc.Recover(ctx); err != nil {
				t.Fatalf("Recover after repair: %v", err)
			}
			seedSceneSignal(t, db, "inc_1", "sig_1", "agent_a", "probe_x", 1, now.Add(-time.Minute))
			ingestScenes(t, svc, ctx, "agent_a", basicScene("scene_1", now, probeTrigger("probe_x", 1, now.Add(-time.Minute))))
			if n := countRows(t, db, `SELECT COUNT(*) FROM scene_reports WHERE id='scene_1'`); n != 1 {
				t.Fatalf("scene_reports rows = %d, want 1", n)
			}
			if n := countRows(t, db, `SELECT COUNT(*) FROM scene_report_refs WHERE report_id='scene_1' AND incident_id='inc_1'`); n != 1 {
				t.Errorf("scene was not filed under the firing incident (refs = %d)", n)
			}
		})
	}
}
