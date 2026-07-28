package store_test

import (
	"context"
	"testing"

	"github.com/nettact/server-core/store/storetest"
)

// The 0023 rename must carry an operator's tuned windows across, not reset them:
// a grace period someone widened to survive a flaky uplink would otherwise
// silently revert to 60s and start confirming faults they had deliberately tuned
// out. It must also leave the alert-era routing keys gone.
func TestMigration0023RenamesConnectivitySettings(t *testing.T) {
	db := storetest.Open(t)
	ctx := context.Background()

	// Legacy rows, as an installation that predates the rename would hold them.
	for _, kv := range [][2]string{
		{"agent_alert_enabled", "0"},
		{"agent_alert_grace_seconds", "600"},
		{"agent_alert_recover_seconds", "120"},
		{"agent_alert_severity", "critical"},
		{"agent_alert_channel_ids", `["chan_1"]`},
	} {
		if _, err := db.ExecContext(ctx,
			`INSERT INTO app_settings(key,value) VALUES(?,?)`, kv[0], kv[1]); err != nil {
			t.Fatalf("seed %s: %v", kv[0], err)
		}
	}

	// Replay the migration's statements against those rows.
	for _, q := range []string{
		`UPDATE app_settings SET key = 'agent_connectivity_enabled'         WHERE key = 'agent_alert_enabled'`,
		`UPDATE app_settings SET key = 'agent_connectivity_grace_seconds'   WHERE key = 'agent_alert_grace_seconds'`,
		`UPDATE app_settings SET key = 'agent_connectivity_recover_seconds' WHERE key = 'agent_alert_recover_seconds'`,
		`DELETE FROM app_settings WHERE key IN ('agent_alert_severity', 'agent_alert_channel_ids')`,
	} {
		if _, err := db.ExecContext(ctx, q); err != nil {
			t.Fatalf("migrate %q: %v", q, err)
		}
	}

	want := map[string]string{
		"agent_connectivity_enabled":         "0",
		"agent_connectivity_grace_seconds":   "600",
		"agent_connectivity_recover_seconds": "120",
	}
	for k, v := range want {
		var got string
		if err := db.Read().QueryRowContext(ctx,
			`SELECT value FROM app_settings WHERE key=?`, k).Scan(&got); err != nil {
			t.Fatalf("read %s: %v", k, err)
		}
		if got != v {
			t.Fatalf("%s = %q, want the operator's %q carried across", k, got, v)
		}
	}
	var leftovers int
	if err := db.Read().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM app_settings WHERE key LIKE 'agent_alert_%'`).Scan(&leftovers); err != nil {
		t.Fatal(err)
	}
	if leftovers != 0 {
		t.Fatalf("%d alert-era keys survived; nothing reads them", leftovers)
	}
}
