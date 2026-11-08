//go:build integration

package jobs

import (
	"context"
	"os"
	"testing"
	"time"

	"cheesetrap/internal/reporting"
	"cheesetrap/internal/store"
	"cheesetrap/internal/store/db"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestInitialReportingClockFloor(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	pools := map[string]*pgxpool.Pool{}
	for _, role := range []string{"MIGRATION", "WORKER", "COLLECTOR"} {
		url := os.Getenv("CHEESETRAP_TEST_JOBS_" + role + "_URL")
		if url == "" {
			t.Fatal("isolated jobs credentials required")
		}
		p, err := store.NewPool(ctx, url)
		if err != nil {
			t.Fatal(err)
		}
		defer p.Close()
		pools[role] = p
	}
	owner, worker, collector := pools["MIGRATION"], pools["WORKER"], pools["COLLECTOR"]
	client, err := NewClient(worker)
	if err != nil {
		t.Fatal(err)
	}
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := owner.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	reset := func() {
		exec("DELETE FROM cheesetrap.report_windows; DELETE FROM cheesetrap.reporting_schedule_versions WHERE version>1; DELETE FROM cheesetrap_river.river_job; DELETE FROM cheesetrap.detection_evidence; DELETE FROM cheesetrap.detection_results; DELETE FROM cheesetrap.detection_completions; DELETE FROM cheesetrap.events; UPDATE cheesetrap.processing_cursors SET ingested_seq=0,detected_seq=0,sealed_before='-infinity'; UPDATE cheesetrap.reporting_schedule_cursor SET next_start=NULL")
	}
	reset()
	defer reset()
	exec("INSERT INTO cheesetrap.sensors(sensor_id,name,engine) VALUES('10000000-0000-4000-8000-000000000303','initial-floor-fixture','cowrie')")
	exec("INSERT INTO cheesetrap.file_generations(file_generation_id,sensor_id,path,device,inode) VALUES('20000000-0000-4000-8000-000000000303','10000000-0000-4000-8000-000000000303','/fixture/events',1,1)")
	var today time.Time
	if err = owner.QueryRow(ctx, "SELECT date_trunc('day',clock_timestamp() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC'").Scan(&today); err != nil {
		t.Fatal(err)
	}
	future := today.AddDate(0, 0, 1)
	const insertEvent = `INSERT INTO cheesetrap.events(sensor_id,file_generation_id,byte_offset,ingestion_seq,schema_version,engine,ingested_at,service,event_type,raw_hash) VALUES('10000000-0000-4000-8000-000000000303','20000000-0000-4000-8000-000000000303',$1,$1,1,'cowrie',$2,'ssh','session.connect',repeat('a',64))`
	seedFuture := func() {
		exec(insertEvent, int64(1), future.Add(12*time.Hour))
		exec("UPDATE cheesetrap.processing_cursors SET ingested_seq=1")
	}
	reconcile := func() {
		t.Helper()
		if _, err := Reconcile(ctx, worker, client); err != nil {
			t.Fatal(err)
		}
	}
	assertNoInitialization := func() {
		t.Helper()
		var clean bool
		if err := owner.QueryRow(ctx, `SELECT (SELECT next_start IS NULL FROM cheesetrap.reporting_schedule_cursor) AND (SELECT sealed_before='-infinity' FROM cheesetrap.processing_cursors) AND NOT EXISTS(SELECT 1 FROM cheesetrap.report_windows) AND NOT EXISTS(SELECT 1 FROM cheesetrap_river.river_job) AND (SELECT count(*)=1 FROM cheesetrap.reporting_schedule_versions)`).Scan(&clean); err != nil || !clean {
			t.Fatal("failed initialization leaked cursor, floor, windows, settings or jobs", err)
		}
	}
	for _, mode := range []string{"empty_startup", "future_event_startup", "first_settings_change", "persisted_anchor"} {
		t.Run(mode, func(t *testing.T) {
			reset()
			wantStart := future
			if mode == "empty_startup" {
				wantStart = today
			} else if mode == "persisted_anchor" {
				exec("UPDATE cheesetrap.reporting_schedule_cursor SET next_start=$1", future)
			} else {
				seedFuture()
			}
			if mode == "first_settings_change" {
				change, err := reporting.ChangeSchedule(ctx, worker, "UTC", 7)
				if err != nil {
					t.Fatal(err)
				}
				if !change.EffectiveFrom.Time.Equal(future.AddDate(0, 0, 1)) {
					t.Errorf("first change ignored future anchor: effective=%s want=%s", change.EffectiveFrom.Time, future.AddDate(0, 0, 1))
				}
			} else {
				reconcile()
			}
			var start, floor pgtype.Timestamptz
			if err := owner.QueryRow(ctx, "SELECT next_start,sealed_before FROM cheesetrap.reporting_schedule_cursor CROSS JOIN cheesetrap.processing_cursors").Scan(&start, &floor); err != nil {
				t.Fatal(err)
			}
			if !start.Time.Equal(wantStart) || !floor.Valid || floor.InfinityModifier != pgtype.Finite || floor.Time.Before(start.Time) {
				t.Errorf("initial anchor is not protected: start=%s floor=%v", start.Time, floor)
			}
			// A prior DB clock could have produced the future first event. Collection
			// now samples the production query after its real processing-cursor lock.
			tx, err := collector.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(context.Background())
			q := db.New(tx)
			cursors, err := q.LockProcessingCursors(ctx)
			if err != nil {
				t.Fatal(err)
			}
			at, err := q.CommitClock(ctx)
			if err != nil {
				t.Fatal(err)
			}
			seq := cursors.IngestedSeq + 1
			if _, err = tx.Exec(ctx, insertEvent, seq, at); err != nil {
				t.Fatal(err)
			}
			if _, err = q.AdvanceIngestedCursor(ctx, seq); err != nil {
				t.Fatal(err)
			}
			if err = tx.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			for range 3 {
				reconcile()
			}
			var membership int
			if err = owner.QueryRow(ctx, "SELECT count(*) FROM cheesetrap.events e JOIN cheesetrap.report_windows w ON e.ingested_at>=w.start_at AND e.ingested_at<w.end_at WHERE e.ingestion_seq=$1", seq).Scan(&membership); err != nil {
				t.Fatal(err)
			}
			if at.Time.Before(start.Time) || membership != 1 {
				t.Fatalf("post-initialization collection escaped coverage: at=%s start=%s memberships=%d", at.Time, start.Time, membership)
			}
		})
	}
	t.Run("river_failure_rolls_back_future_anchor", func(t *testing.T) {
		reset()
		seedFuture()
		exec(`CREATE FUNCTION cheesetrap_river.test_initial_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected'; END $$; CREATE TRIGGER test_initial_failure BEFORE INSERT ON cheesetrap_river.river_job FOR EACH ROW EXECUTE FUNCTION cheesetrap_river.test_initial_failure()`)
		_, err := Reconcile(ctx, worker, client)
		exec("DROP TRIGGER test_initial_failure ON cheesetrap_river.river_job; DROP FUNCTION cheesetrap_river.test_initial_failure()")
		if err == nil {
			t.Fatal("River failure ignored")
		}
		assertNoInitialization()
		reconcile()
	})
	t.Run("settings_failure_rolls_back_future_anchor", func(t *testing.T) {
		reset()
		seedFuture()
		exec(`CREATE FUNCTION cheesetrap.test_initial_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected'; END $$; CREATE TRIGGER test_initial_failure BEFORE INSERT ON cheesetrap.reporting_schedule_versions FOR EACH ROW EXECUTE FUNCTION cheesetrap.test_initial_failure()`)
		_, err := reporting.ChangeSchedule(ctx, worker, "UTC", 7)
		exec("DROP TRIGGER test_initial_failure ON cheesetrap.reporting_schedule_versions; DROP FUNCTION cheesetrap.test_initial_failure()")
		if err == nil {
			t.Fatal("settings failure ignored")
		}
		assertNoInitialization()
	})
}
