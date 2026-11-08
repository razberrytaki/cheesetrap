//go:build integration

package jobs

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"cheesetrap/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
)

type detectionCommitObserver struct{ afterCommit func() }

func (*detectionCommitObserver) TraceQueryStart(ctx context.Context, _ *pgx.Conn, _ pgx.TraceQueryStartData) context.Context {
	return ctx
}
func (o *detectionCommitObserver) TraceQueryEnd(_ context.Context, _ *pgx.Conn, d pgx.TraceQueryEndData) {
	if d.Err == nil && strings.EqualFold(d.CommandTag.String(), "COMMIT") {
		o.afterCommit()
	}
}

func TestDetectionWorkerMultipleAtomicPasses(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
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
	collector, err := store.NewPool(ctx, os.Getenv("CHEESETRAP_TEST_JOBS_COLLECTOR_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer collector.Close()
	exec := func(sql string) {
		t.Helper()
		if _, err := owner.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	reset := func() {
		exec(`DELETE FROM cheesetrap.detection_evidence; DELETE FROM cheesetrap.detection_results; DELETE FROM cheesetrap.detection_completions; DELETE FROM cheesetrap.events; UPDATE cheesetrap.processing_cursors SET ingested_seq=0,detected_seq=0`)
	}
	reset()
	defer reset()
	exec(`INSERT INTO cheesetrap.sensors(sensor_id,name,engine) VALUES('10000000-0000-4000-8000-000000000306','detection-worker','cowrie');
 INSERT INTO cheesetrap.file_generations(file_generation_id,sensor_id,path,device,inode) VALUES('20000000-0000-4000-8000-000000000306','10000000-0000-4000-8000-000000000306','/fixture/detection-worker',1,1)`)
	for _, mode := range []string{"drain", "cancel_between_passes", "storage_restricted_between_passes"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("CHEESETRAP_STORAGE_PATHS", "")
			reset()
			exec(`INSERT INTO cheesetrap.events(sensor_id,file_generation_id,byte_offset,ingestion_seq,schema_version,engine,service,event_type,raw_hash)
 SELECT '10000000-0000-4000-8000-000000000306','20000000-0000-4000-8000-000000000306',n,n,1,'cowrie','ssh','cowrie.session.connect',repeat('a',64) FROM generate_series(1,1001)n;
 UPDATE cheesetrap.processing_cursors SET ingested_seq=1001`)
			workCtx, stop := context.WithCancel(ctx)
			defer stop()
			commits := 0
			var prefix int64
			observer := &detectionCommitObserver{afterCommit: func() {
				commits++
				if commits != 1 {
					return
				}
				// A collector can acquire the same cursor between worker passes. The
				// visible completion prefix and cursor must already be committed together.
				tx, err := collector.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Rollback(ctx)
				if err = tx.QueryRow(ctx, "SELECT detected_seq FROM cheesetrap.processing_cursors WHERE singleton FOR UPDATE NOWAIT").Scan(&prefix); err != nil {
					t.Fatal("worker kept cursor locked between passes", err)
				}
				var completed int64
				if err = owner.QueryRow(ctx, "SELECT count(*) FROM cheesetrap.detection_completions").Scan(&completed); err != nil || completed != prefix || prefix < 1 || prefix > 1000 {
					t.Fatalf("partial prefix: cursor=%d completions=%d error=%v", prefix, completed, err)
				}
				if mode == "cancel_between_passes" {
					stop()
				}
				if mode == "storage_restricted_between_passes" {
					t.Setenv("CHEESETRAP_STORAGE_PATHS", "/nonexistent-cheesetrap-detection-worker-test")
				}
			}}
			cfg := worker.Config()
			cfg.ConnConfig.Tracer = observer
			traced, err := pgxpool.NewWithConfig(ctx, cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer traced.Close()
			err = (&detectionWorker{pool: traced}).Work(workCtx, nil)
			var detected, completed int64
			if scanErr := owner.QueryRow(ctx, "SELECT detected_seq,(SELECT count(*) FROM cheesetrap.detection_completions) FROM cheesetrap.processing_cursors").Scan(&detected, &completed); scanErr != nil {
				t.Fatal(scanErr)
			}
			if mode == "drain" {
				if err != nil || commits < 2 || detected != 1001 || completed != 1001 {
					t.Fatalf("one Work did not drain multiple atomic prefixes: commits=%d detected=%d completed=%d err=%v", commits, detected, completed, err)
				}
			} else {
				if err == nil || commits != 1 || detected != prefix || completed != prefix {
					t.Fatalf("continued after stop: commits=%d detected=%d prefix=%d err=%v", commits, detected, prefix, err)
				}
				if mode == "storage_restricted_between_passes" {
					var snooze *river.JobSnoozeError
					if !errors.As(err, &snooze) || snooze.Duration != time.Minute {
						t.Fatalf("storage restriction was not rechecked: %v", err)
					}
				}
				if mode == "cancel_between_passes" && !errors.Is(err, context.Canceled) {
					t.Fatalf("cancellation not propagated: %v", err)
				}
			}
		})
	}
}
