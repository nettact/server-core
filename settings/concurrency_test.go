package settings

import (
	"context"
	"testing"
	"time"

	"github.com/nettact/server-core/store/storetest"
)

func TestReadsStayResponsiveWhileWriterTransactionIsOpen(t *testing.T) {
	db := storetest.Open(t)
	ctx := context.Background()
	s := New(db)
	if err := s.Set(ctx, KeyDiagEnabled, "1"); err != nil {
		t.Fatalf("seed setting: %v", err)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin writer: %v", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `UPDATE app_settings SET value='0' WHERE key=?`, KeyDiagEnabled); err != nil {
		t.Fatalf("hold writer: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		if _, err := s.Get(ctx, KeyDiagEnabled); err != nil {
			done <- err
			return
		}
		_, err := s.All(ctx)
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("read settings: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("settings reads waited on the single write connection")
	}
}
