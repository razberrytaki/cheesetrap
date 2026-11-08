//go:build integration

package jobs

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"cheesetrap/internal/retention"
	"cheesetrap/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
)

func TestRetentionWorkerBusyLocks(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	t.Setenv("CHEESETRAP_STORAGE_PATHS", "")
	owner, err := store.NewPool(ctx, os.Getenv("CHEESETRAP_TEST_JOBS_MIGRATION_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	worker, err := store.NewPool(ctx, os.Getenv("CHEESETRAP_TEST_JOBS_WORKER_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer worker.Close()
	for _, table := range []string{"processing_cursors", "report_draft_lock"} {
		t.Run(table, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			gate, err := owner.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer gate.Rollback(ctx)
			if _, err = gate.Exec(ctx, "SELECT singleton FROM cheesetrap."+table+" WHERE singleton FOR UPDATE"); err != nil {
				t.Fatal(err)
			}
			acquisitions := worker.Stat().AcquireCount()
			result := make(chan error, 1)
			go func() { result <- (&retentionWorker{pool: worker}).Work(ctx, nil) }()
			tick := time.NewTicker(10 * time.Millisecond)
			defer tick.Stop()
			// Empty storage paths do not acquire a connection. Three acquisitions
			// prove the same Work invocation retried admission. Observe it between
			// attempts with no retained connection before releasing the real lock.
			for worker.Stat().AcquireCount()-acquisitions < 3 || worker.Stat().AcquiredConns() != 0 {
				select {
				case err := <-result:
					t.Fatalf("busy invocation returned before retrying admission: %v", err)
				case <-ctx.Done():
					t.Fatal("busy admission did not retry and release its connection", ctx.Err())
				case <-tick.C:
				}
			}
			if err = gate.Rollback(ctx); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-result:
				if err != nil {
					t.Fatal("original Work invocation did not complete after unlock", err)
				}
			case <-ctx.Done():
				t.Fatal("original Work invocation did not recover", ctx.Err())
			}
		})
	}
}

func TestRetentionWorkerRealFailure(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	t.Setenv("CHEESETRAP_STORAGE_PATHS", "")
	owner, err := store.NewPool(ctx, os.Getenv("CHEESETRAP_TEST_JOBS_MIGRATION_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	worker, err := store.NewPool(ctx, os.Getenv("CHEESETRAP_TEST_JOBS_WORKER_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer worker.Close()
	_, err = owner.Exec(ctx, `CREATE FUNCTION cheesetrap.test_retention_worker_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'worker_cleanup_fault'; END $$; CREATE TRIGGER test_retention_worker_failure BEFORE UPDATE ON cheesetrap.retention_status FOR EACH STATEMENT EXECUTE FUNCTION cheesetrap.test_retention_worker_failure()`)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Exec(ctx, `DROP TRIGGER test_retention_worker_failure ON cheesetrap.retention_status; DROP FUNCTION cheesetrap.test_retention_worker_failure()`)
	err = (&retentionWorker{pool: worker}).Work(ctx, nil)
	var snooze *river.JobSnoozeError
	if !errors.Is(err, retention.ErrCleanup) || errors.As(err, &snooze) {
		t.Fatal("real failure snoozed", err)
	}
}

func TestRetentionRiverDeferralRecovery(t *testing.T) {
	// Two full20s admission horizons must durably snooze before recovery.
	// This test budget leaves time for River polling and the final successful job.
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	t.Setenv("CHEESETRAP_STORAGE_PATHS", "")
	owner, err := store.NewPool(ctx, os.Getenv("CHEESETRAP_TEST_JOBS_MIGRATION_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	worker, err := store.NewPool(ctx, os.Getenv("CHEESETRAP_TEST_JOBS_WORKER_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer worker.Close()
	gate, err := owner.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Rollback(ctx)
	if _, err = gate.Exec(ctx, `SELECT singleton FROM cheesetrap.processing_cursors WHERE singleton FOR UPDATE`); err != nil {
		t.Fatal(err)
	}
	workers := river.NewWorkers()
	river.AddWorker(workers, &retentionWorker{pool: worker})
	client, err := river.NewClient(riverpgxv5.New(worker), &river.Config{Schema: "cheesetrap_river", Workers: workers, Queues: map[string]river.QueueConfig{"retention_lock_test": {MaxWorkers: 1}}, PollOnly: true, FetchPollInterval: 100 * time.Millisecond, ReindexerIndexNames: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	unique := activeUnique()
	unique.ByQueue = true
	job, err := client.Insert(ctx, RetentionArgs{}, &river.InsertOpts{Queue: "retention_lock_test", UniqueOpts: unique})
	if err != nil {
		t.Fatal(err)
	}
	if job.UniqueSkippedAsDuplicate || job.Job.Queue != "retention_lock_test" {
		t.Fatal("test job reused a different queue", job.Job.ID)
	}
	defer owner.Exec(context.Background(), `DELETE FROM cheesetrap_river.river_job WHERE id=$1`, job.Job.ID)
	if err = client.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer func() {
		stopCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if err := client.Stop(stopCtx); err != nil {
			t.Error(err)
		}
	}()
	started := time.Now()
	gateHeld, lastGateActivity := true, started
	wait := func(done func(string, int, int, int) bool) {
		t.Helper()
		lastState, lastSnoozes, lastAttempt := "", -1, -1
		tick := time.NewTicker(20 * time.Millisecond)
		defer tick.Stop()
		for {
			// Keep the intentionally held test transaction active across two
			// horizons; the unchanged pool's30s idle timeout would release it.
			if gateHeld && time.Since(lastGateActivity) >= 5*time.Second {
				if _, err := gate.Exec(ctx, "SELECT 1"); err != nil {
					t.Fatal("test lock holder lost its transaction", err)
				}
				lastGateActivity = time.Now()
			}
			var state string
			var snoozes, attempt, failures int
			err := owner.QueryRow(ctx, `SELECT state::text,coalesce((metadata->>'snoozes')::int,0),attempt,coalesce(cardinality(errors),0) FROM cheesetrap_river.river_job WHERE id=$1`, job.Job.ID).Scan(&state, &snoozes, &attempt, &failures)
			if err != nil {
				t.Fatal(err)
			}
			if state != lastState || snoozes != lastSnoozes || attempt != lastAttempt {
				t.Logf("retention River transition elapsed=%s state=%s snoozes=%d attempt=%d pool_acquires=%d pool_held=%d", time.Since(started), state, snoozes, attempt, worker.Stat().AcquireCount(), worker.Stat().AcquiredConns())
				lastState, lastSnoozes, lastAttempt = state, snoozes, attempt
			}
			if failures != 0 {
				t.Fatal("admission recorded failed attempt", failures)
			}
			if done(state, snoozes, attempt, failures) {
				return
			}
			select {
			case <-ctx.Done():
				t.Fatal("durable deferral/progress missing", ctx.Err())
			case <-tick.C:
			}
		}
	}
	wait(func(state string, snoozes, attempt, failures int) bool { return state != "completed" && snoozes >= 2 })
	if err = gate.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
		t.Fatal(err)
	}
	gateHeld = false
	wait(func(state string, snoozes, attempt, failures int) bool {
		return state == "completed" && snoozes >= 2 && attempt == 1
	})
}

// More than one maximum SQL batch must complete in one Work invocation.
func TestRetentionWorkerDrainsBacklog(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	t.Setenv("CHEESETRAP_STORAGE_PATHS", t.TempDir()+"/missing")
	owner, err := store.NewPool(ctx, os.Getenv("CHEESETRAP_TEST_JOBS_MIGRATION_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	worker, err := store.NewPool(ctx, os.Getenv("CHEESETRAP_TEST_JOBS_WORKER_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer worker.Close()
	if _, err = owner.Exec(ctx, `CREATE TABLE cheesetrap.test_retention_worker_passes (deleted bigint, transaction_id bigint);
 CREATE FUNCTION cheesetrap.test_retention_worker_pass() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,cheesetrap AS $$ BEGIN INSERT INTO cheesetrap.test_retention_worker_passes SELECT count(*),txid_current() FROM removed WHERE action='retention-throughput-test'; RETURN NULL; END $$;
 CREATE TRIGGER test_retention_worker_pass AFTER DELETE ON cheesetrap.audit REFERENCING OLD TABLE AS removed FOR EACH STATEMENT EXECUTE FUNCTION cheesetrap.test_retention_worker_pass()`); err != nil {
		t.Fatal(err)
	}
	defer owner.Exec(context.Background(), `DROP TRIGGER test_retention_worker_pass ON cheesetrap.audit; DROP FUNCTION cheesetrap.test_retention_worker_pass(); DROP TABLE cheesetrap.test_retention_worker_passes`)

	if _, err = owner.Exec(ctx, `INSERT INTO cheesetrap.audit(action,details,created_at) SELECT 'retention-throughput-test','{}',now()-interval '181 days' FROM generate_series(1,2501)`); err != nil {
		t.Fatal(err)
	}
	defer owner.Exec(context.Background(), `DELETE FROM cheesetrap.audit WHERE action='retention-throughput-test'`)
	if err = (&retentionWorker{pool: worker}).Work(ctx, nil); err != nil {
		t.Fatal(err)
	}
	var left int
	if err = owner.QueryRow(ctx, `SELECT count(*) FROM cheesetrap.audit WHERE action='retention-throughput-test'`).Scan(&left); err != nil {
		t.Fatal(err)
	}
	if left != 0 {
		t.Fatalf("one Work left %d of 2501 expired rows", left)
	}
	var total, largest, transactions int
	if err = owner.QueryRow(ctx, `SELECT sum(deleted),max(deleted),count(DISTINCT transaction_id) FROM cheesetrap.test_retention_worker_passes`).Scan(&total, &largest, &transactions); err != nil {
		t.Fatal(err)
	}
	if total != 2501 || largest != 1000 || transactions != 4 {
		t.Fatalf("cleanup did not commit bounded passes: total=%d max=%d transactions=%d", total, largest, transactions)
	}
	var available bool
	if err = owner.QueryRow(ctx, `SELECT available FROM cheesetrap.storage_status WHERE component='worker'`).Scan(&available); err != nil || available {
		t.Fatal("restricted storage sample not exercised", available, err)
	}
}

func TestRetentionWorkerSQLTimeoutIsFailureAndRollsBack(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	t.Setenv("CHEESETRAP_STORAGE_PATHS", "")
	owner, err := store.NewPool(ctx, os.Getenv("CHEESETRAP_TEST_JOBS_MIGRATION_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	worker, err := store.NewPool(ctx, os.Getenv("CHEESETRAP_TEST_JOBS_WORKER_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer worker.Close()
	if _, err = owner.Exec(ctx, `INSERT INTO cheesetrap.audit(action,created_at) VALUES('retention-timeout-test',now()-interval '181 days');
 CREATE FUNCTION cheesetrap.test_retention_worker_timeout() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(6); RETURN NEW; END $$;
 CREATE TRIGGER test_retention_worker_timeout BEFORE UPDATE ON cheesetrap.retention_status FOR EACH ROW EXECUTE FUNCTION cheesetrap.test_retention_worker_timeout()`); err != nil {
		t.Fatal(err)
	}
	defer owner.Exec(context.Background(), `DROP TRIGGER test_retention_worker_timeout ON cheesetrap.retention_status; DROP FUNCTION cheesetrap.test_retention_worker_timeout(); DELETE FROM cheesetrap.audit WHERE action='retention-timeout-test'`)
	err = (&retentionWorker{pool: worker}).Work(ctx, nil)
	var snooze *river.JobSnoozeError
	if !errors.Is(err, context.DeadlineExceeded) || errors.As(err, &snooze) {
		t.Fatal("SQL cancellation must fail rather than snooze", err)
	}
	var left int
	if err = owner.QueryRow(ctx, `SELECT count(*) FROM cheesetrap.audit WHERE action='retention-timeout-test'`).Scan(&left); err != nil || left != 1 {
		t.Fatal("timed-out cleanup committed deletion", left, err)
	}
}
