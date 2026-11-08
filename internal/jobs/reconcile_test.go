//go:build integration

package jobs

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"cheesetrap/internal/reporting"
	"cheesetrap/internal/store"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestReconcile(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	pools := map[string]*pgxpool.Pool{}
	for _, role := range []string{"MIGRATION", "WORKER"} {
		raw := os.Getenv("CHEESETRAP_TEST_JOBS_" + role + "_URL")
		if raw == "" {
			t.Fatal("isolated jobs credentials required")
		}
		p, err := store.NewPool(ctx, raw)
		if err != nil {
			t.Fatal(err)
		}
		defer p.Close()
		pools[role] = p
	}
	owner, worker := pools["MIGRATION"], pools["WORKER"]
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
	count := func(sql string) int {
		t.Helper()
		var n int
		if err := owner.QueryRow(ctx, sql).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	var today time.Time
	if err = owner.QueryRow(ctx, "SELECT date_trunc('day',clock_timestamp() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC'").Scan(&today); err != nil {
		t.Fatal(err)
	}
	exec("INSERT INTO cheesetrap.sensors(sensor_id,name,engine) VALUES('10000000-0000-4000-8000-000000000302','jobs-fixture','cowrie')")
	exec("INSERT INTO cheesetrap.file_generations(file_generation_id,sensor_id,path,device,inode) VALUES('20000000-0000-4000-8000-000000000302','10000000-0000-4000-8000-000000000302','/fixture/events',1,1)")
	exec(`INSERT INTO cheesetrap.events(sensor_id,file_generation_id,byte_offset,ingestion_seq,schema_version,engine,ingested_at,service,event_type,raw_hash) SELECT '10000000-0000-4000-8000-000000000302','20000000-0000-4000-8000-000000000302',n,n,1,'cowrie',$1::timestamptz+(n-1)*interval '1 day','ssh','session.connect',repeat('a',64) FROM generate_series(1,3)n`, today.AddDate(0, 0, -3))
	exec("UPDATE cheesetrap.processing_cursors SET ingested_seq=3")
	reconcile := func() {
		t.Helper()
		if _, err := Reconcile(ctx, worker, client); err != nil {
			t.Fatal(err)
		}
	}
	t.Run("atomic_domain_and_river_insert", func(t *testing.T) {
		exec(`CREATE FUNCTION cheesetrap_river.test_fail_insert() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected'; END $$; CREATE TRIGGER test_fail_insert BEFORE INSERT ON cheesetrap_river.river_job FOR EACH ROW EXECUTE FUNCTION cheesetrap_river.test_fail_insert()`)
		_, err := Reconcile(ctx, worker, client)
		exec("DROP TRIGGER test_fail_insert ON cheesetrap_river.river_job; DROP FUNCTION cheesetrap_river.test_fail_insert()")
		if err == nil {
			t.Fatal("River InsertTx failure did not fail reconciliation")
		}
		if count("SELECT count(*) FROM cheesetrap.report_windows") != 0 || count("SELECT count(*) FROM cheesetrap.reporting_schedule_cursor WHERE next_start IS NOT NULL") != 0 || count("SELECT count(*) FROM cheesetrap.processing_cursors WHERE sealed_before<>'-infinity'") != 0 || count("SELECT count(*) FROM cheesetrap_river.river_job") != 0 {
			t.Fatal("InsertTx failure leaked domain or queue state")
		}
	})
	reconcile()
	if count("SELECT count(*) FROM cheesetrap.report_windows WHERE state='sealed'") != 3 || count("SELECT count(*) FROM cheesetrap.report_windows WHERE state='open'") != 1 {
		t.Fatal("startup did not replay ingestion backlog including open interval")
	}
	if count("SELECT count(*) FROM cheesetrap_river.river_job") != 5 {
		t.Fatal("detection, window or retention jobs missing")
	}
	t.Run("concurrent_duplicate_and_lost_jobs", func(t *testing.T) {
		var wg sync.WaitGroup
		for range 2 {
			wg.Go(func() {
				if _, err := Reconcile(ctx, worker, client); err != nil {
					t.Error(err)
				}
			})
		}
		wg.Wait()
		if count("SELECT count(*) FROM cheesetrap_river.river_job") != 5 {
			t.Fatal("duplicate active jobs")
		}
		exec("DELETE FROM cheesetrap_river.river_job")
		reconcile()
		if count("SELECT count(*) FROM cheesetrap_river.river_job") != 5 {
			t.Fatal("lost jobs not recovered")
		}
		exec("UPDATE cheesetrap_river.river_job SET state=CASE WHEN id%2=0 THEN 'cancelled'::cheesetrap_river.river_job_state ELSE 'discarded'::cheesetrap_river.river_job_state END,finalized_at=clock_timestamp()")
		reconcile()
		if count("SELECT count(*) FROM cheesetrap_river.river_job WHERE state='available'") != 5 {
			t.Fatal("cancelled/discarded jobs not repaired")
		}
	})
	t.Run("change_preserves_existing_windows", func(t *testing.T) {
		var before string
		if err := owner.QueryRow(ctx, "SELECT jsonb_agg(to_jsonb(w) ORDER BY start_at)::text FROM cheesetrap.report_windows w").Scan(&before); err != nil {
			t.Fatal(err)
		}
		first, err := reporting.ChangeSchedule(ctx, worker, "Asia/Tokyo", 7)
		if err != nil {
			t.Fatal(err)
		}
		last, err := reporting.ChangeSchedule(ctx, worker, "America/New_York", 2)
		if err != nil {
			t.Fatal(err)
		}
		if !first.EffectiveFrom.Time.Equal(today.AddDate(0, 0, 1)) || !last.EffectiveFrom.Time.Equal(first.EffectiveFrom.Time) || last.Version <= first.Version {
			t.Fatal("changes did not target next unopened interval")
		}
		reconcile()
		var after string
		if err = owner.QueryRow(ctx, "SELECT jsonb_agg(to_jsonb(w) ORDER BY start_at)::text FROM cheesetrap.report_windows w").Scan(&after); err != nil || before != after {
			t.Fatal("settings change rewrote existing interval")
		}
	})
	t.Run("real_river_workers_and_shutdown", func(t *testing.T) {
		runCtx, stop := context.WithCancel(ctx)
		done := make(chan error, 1)
		go func() { done <- Run(runCtx, os.Getenv("CHEESETRAP_TEST_JOBS_WORKER_URL"), 5*time.Second) }()
		deadline := time.NewTimer(15 * time.Second)
		defer deadline.Stop()
		ticker := time.NewTicker(50 * time.Millisecond)
		defer ticker.Stop()
	wait:
		for {
			select {
			case err := <-done:
				t.Fatal("worker exited before completion", err)
			case <-deadline.C:
				stop()
				<-done
				t.Fatal("real River workers did not process durable jobs")
			case <-ticker.C:
				if count("SELECT count(*) FROM cheesetrap.report_windows WHERE state='ready'") == 3 {
					break wait
				}
			}
		}
		if count("SELECT detected_seq::integer FROM cheesetrap.processing_cursors") != 3 || count("SELECT count(*) FROM cheesetrap_river.river_job WHERE queue NOT IN ('detection','windows','drafts','retention')") != 0 {
			t.Fatal("worker queues or detection progress wrong")
		}
		stop()
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(6 * time.Second):
			t.Fatal("worker did not stop gracefully")
		}
	})
	t.Run("bounded_downtime_and_historical_schedule_versions", func(t *testing.T) {
		exec("TRUNCATE cheesetrap.report_window_completions,cheesetrap.report_candidates; DELETE FROM cheesetrap.report_windows; DELETE FROM cheesetrap.reporting_schedule_versions WHERE version>1; UPDATE cheesetrap.reporting_schedule_cursor SET next_start=NULL; DELETE FROM cheesetrap_river.river_job")
		exec("UPDATE cheesetrap.events SET ingested_at=$1::timestamptz+(ingestion_seq-1)*interval '1 day'", today.AddDate(0, 0, -100))
		exec("INSERT INTO cheesetrap.reporting_schedule_versions(timezone,period_days,effective_from) VALUES('UTC',7,$1),('UTC',2,$2),('Asia/Tokyo',2,$2)", today.AddDate(0, 0, -65), today.AddDate(0, 0, -51))
		more, err := Reconcile(ctx, worker, client)
		if err != nil || !more {
			t.Fatal("long downtime was not bounded", err)
		}
		if count("SELECT count(*) FROM cheesetrap.report_windows") != reporting.CatchUpLimit {
			t.Fatal("catch-up exceeded bounded pass")
		}
		// A new change now must not replace historical pending versions while the
		// persistent cursor remains in the distant past.
		change, err := reporting.ChangeSchedule(ctx, worker, "UTC", 1)
		if err != nil {
			t.Fatal(err)
		}
		if !change.EffectiveFrom.Time.After(time.Now()) {
			t.Fatal("change applied retroactively during catch-up")
		}
		for i := 0; i < 10 && more; i++ {
			more, err = Reconcile(ctx, worker, client)
			if err != nil {
				t.Fatal(err)
			}
		}
		if more {
			t.Fatal("bounded catch-up did not converge")
		}
		if count("SELECT count(*) FROM cheesetrap.report_windows w WHERE state='sealed' AND NOT EXISTS(SELECT 1 FROM cheesetrap_river.river_job j WHERE j.kind='seal_window' AND j.args->>'window_id'=w.window_id::text)") != 0 {
			t.Fatal("newly sealed intervals committed without their River job")
		}

		// Recovery must eventually inspect later pending windows even when the
		// oldest page already has active jobs waiting for detection completion.
		exec("DELETE FROM cheesetrap_river.river_job WHERE kind='seal_window' AND args->>'window_id'=(SELECT window_id::text FROM cheesetrap.report_windows WHERE state='sealed' ORDER BY start_at DESC LIMIT 1)")
		for range 4 {
			reconcile()
		}
		if count("SELECT count(*) FROM cheesetrap.report_windows w WHERE state='sealed' AND NOT EXISTS(SELECT 1 FROM cheesetrap_river.river_job j WHERE j.kind='seal_window' AND j.args->>'window_id'=w.window_id::text)") != 0 {
			t.Fatal("repair starved a later missing window job behind active old jobs")
		}
		if count("SELECT count(*) FROM (SELECT start_at,lag(end_at) OVER(ORDER BY start_at) prior FROM cheesetrap.report_windows) x WHERE prior IS NOT NULL AND prior<>start_at") != 0 {
			t.Fatal("date/period change left interval gap or overlap")
		}
		if count("SELECT count(*) FROM cheesetrap.report_windows w JOIN cheesetrap.reporting_schedule_versions s ON s.version=w.settings_version WHERE s.timezone='Asia/Tokyo'") == 0 || count("SELECT count(*) FROM cheesetrap.report_windows w JOIN cheesetrap.reporting_schedule_versions s ON s.version=w.settings_version WHERE s.timezone='UTC' AND s.period_days=2") != 0 {
			t.Fatal("historical pending schedule or same-boundary latest version lost")
		}
	})
	t.Run("empty_install_and_first_settings_change", func(t *testing.T) {
		exec("TRUNCATE cheesetrap.report_window_completions,cheesetrap.report_candidates; DELETE FROM cheesetrap.report_windows; DELETE FROM cheesetrap.reporting_schedule_versions WHERE version>1; DELETE FROM cheesetrap_river.river_job; DELETE FROM cheesetrap.detection_completions; DELETE FROM cheesetrap.events; UPDATE cheesetrap.processing_cursors SET ingested_seq=0,detected_seq=0,sealed_before='-infinity'; UPDATE cheesetrap.reporting_schedule_cursor SET next_start=NULL")
		change, err := reporting.ChangeSchedule(ctx, worker, "Asia/Tokyo", 2)
		if err != nil {
			t.Fatal(err)
		}
		var anchor time.Time
		if err = owner.QueryRow(ctx, "SELECT next_start FROM cheesetrap.reporting_schedule_cursor").Scan(&anchor); err != nil {
			t.Fatal("first settings change did not durably initialize the schedule", err)
		}
		if !change.EffectiveFrom.Time.Equal(anchor.AddDate(0, 0, 1)) {
			t.Fatal("first change replaced the initial current interval")
		}
		reconcile()
		if count("SELECT count(*) FROM cheesetrap.report_windows WHERE state='open' AND settings_version=1") != 1 || count("SELECT count(*) FROM cheesetrap_river.river_job WHERE kind<>'retention_cleanup'") != 0 || count("SELECT count(*) FROM cheesetrap_river.river_job WHERE kind='retention_cleanup'") != 1 {
			t.Fatal("empty installation replayed arbitrary history or queued nonexistent work")
		}
	})

}
