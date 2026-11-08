//go:build integration

package retention

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"cheesetrap/internal/store"
)

func TestRetentionLockAdmission(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	owner, err := store.NewPool(ctx, os.Getenv("CHEESETRAP_TEST_RETENTION_MIGRATION_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	worker, err := store.NewPool(ctx, os.Getenv("CHEESETRAP_TEST_RETENTION_WORKER_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer worker.Close()
	// A historical evaluation time avoids expiring fixtures belonging to other tests.
	at := time.Date(1900, 1, 1, 0, 0, 0, 0, time.UTC)
	snapshot := func() string {
		t.Helper()
		var s string
		err := owner.QueryRow(ctx, `SELECT json_build_array((SELECT row_to_json(s) FROM cheesetrap.retention_status s),(SELECT count(*) FROM cheesetrap.events),(SELECT count(*) FROM cheesetrap.detection_results),(SELECT count(*) FROM cheesetrap.evidence_chunk_members))::text`).Scan(&s)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	for _, table := range []string{"processing_cursors", "report_draft_lock"} {
		t.Run(table, func(t *testing.T) {
			gate, err := owner.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer gate.Rollback(ctx)
			if _, err = gate.Exec(ctx, "SELECT singleton FROM cheesetrap."+table+" WHERE singleton FOR UPDATE"); err != nil {
				t.Fatal(err)
			}
			before := snapshot()
			started := time.Now()
			admissionCtx, cancelAdmission := context.WithTimeout(ctx, 500*time.Millisecond)
			p, err := Cleanup(admissionCtx, worker, at, 1)
			cancelAdmission()
			t.Logf("contended cleanup returned after %s", time.Since(started))
			if err == nil || err.Error() != "retention_cleanup_busy" || p != (Progress{}) {
				t.Fatalf("expected explicit busy without cleanup: progress=%+v err=%v", p, err)
			}
			if acquired := worker.Stat().AcquiredConns(); acquired != 0 {
				t.Fatalf("busy admission retained %d pool connections", acquired)
			}
			if after := snapshot(); after != before {
				t.Fatalf("contended cleanup mutated data: %s -> %s", before, after)
			}
			if table == "report_draft_lock" {
				probe, e := owner.Begin(ctx)
				if e != nil {
					t.Fatal(e)
				}
				defer probe.Rollback(ctx)
				if _, e = probe.Exec(ctx, `SELECT singleton FROM cheesetrap.processing_cursors WHERE singleton FOR UPDATE NOWAIT`); e != nil {
					t.Fatal("retained cursor while draft is busy", e)
				}
				if e = probe.Rollback(ctx); e != nil {
					t.Fatal(e)
				}
			}
			if err = gate.Rollback(ctx); err != nil {
				t.Fatal(err)
			}
			if _, err = Cleanup(ctx, worker, at, 1); err != nil {
				t.Fatal("did not progress after holder released", err)
			}
		})
	}
	t.Run("real_failure_is_not_busy", func(t *testing.T) {
		_, err := owner.Exec(ctx, `CREATE FUNCTION cheesetrap.test_retention_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'retention_fault'; END $$; CREATE TRIGGER test_retention_failure BEFORE UPDATE ON cheesetrap.retention_status FOR EACH STATEMENT EXECUTE FUNCTION cheesetrap.test_retention_failure()`)
		if err != nil {
			t.Fatal(err)
		}
		defer owner.Exec(ctx, `DROP TRIGGER test_retention_failure ON cheesetrap.retention_status; DROP FUNCTION cheesetrap.test_retention_failure()`)
		if _, err = Cleanup(ctx, worker, at, 1); !errors.Is(err, ErrCleanup) {
			t.Fatal("real cleanup error hidden", err)
		}
	})

	t.Run("late_failure_rolls_back_deletions", func(t *testing.T) {
		const id = "10000000-0000-4000-8000-000000009902"
		_, err := owner.Exec(ctx, `INSERT INTO cheesetrap.audit(audit_id,action,details,created_at) VALUES($1,'retention-lock-fixture','{}',now()-interval '200 days')`, id)
		if err != nil {
			t.Fatal(err)
		}
		defer owner.Exec(ctx, `DELETE FROM cheesetrap.audit WHERE audit_id=$1`, id)
		_, err = owner.Exec(ctx, `CREATE FUNCTION cheesetrap.test_retention_late_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'after_deletion'; END $$; CREATE TRIGGER test_retention_late_failure BEFORE UPDATE ON cheesetrap.retention_status FOR EACH STATEMENT EXECUTE FUNCTION cheesetrap.test_retention_late_failure()`)
		if err != nil {
			t.Fatal(err)
		}
		defer owner.Exec(ctx, `DROP TRIGGER test_retention_late_failure ON cheesetrap.retention_status; DROP FUNCTION cheesetrap.test_retention_late_failure()`)
		p, err := Cleanup(ctx, worker, time.Now().UTC(), 100)
		if !errors.Is(err, ErrCleanup) || p != (Progress{}) {
			t.Fatalf("late failure not atomic: %+v %v", p, err)
		}
		var exists bool
		if err = owner.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM cheesetrap.audit WHERE audit_id=$1)`, id).Scan(&exists); err != nil || !exists {
			t.Fatal("deletion committed on failure", err)
		}
		probe, err := owner.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer probe.Rollback(ctx)
		for _, table := range []string{"processing_cursors", "report_draft_lock"} {
			if _, err = probe.Exec(ctx, "SELECT singleton FROM cheesetrap."+table+" WHERE singleton FOR UPDATE NOWAIT"); err != nil {
				t.Fatal("lock leaked on error", err)
			}
		}
	})
	t.Run("cancelled_is_not_busy", func(t *testing.T) {
		stopped, stop := context.WithCancel(ctx)
		stop()
		if _, err := Cleanup(stopped, worker, at, 1); !errors.Is(err, context.Canceled) {
			t.Fatal("cancellation hidden", err)
		}
	})
	t.Run("missing_singleton_is_not_busy", func(t *testing.T) {
		if _, err := owner.Exec(ctx, `DELETE FROM cheesetrap.report_draft_lock`); err != nil {
			t.Fatal(err)
		}
		defer owner.Exec(ctx, `INSERT INTO cheesetrap.report_draft_lock(singleton) VALUES(true)`)
		if _, err := Cleanup(ctx, worker, at, 1); !errors.Is(err, ErrCleanup) {
			t.Fatal("missing singleton hidden", err)
		}
	})
}
