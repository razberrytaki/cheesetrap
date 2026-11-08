//go:build integration

package reporting

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"cheesetrap/internal/detection"
	"cheesetrap/internal/store"
	"cheesetrap/internal/store/db"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestSealWindow(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	pools := map[string]*pgxpool.Pool{}
	for _, role := range []string{"MIGRATION", "COLLECTOR", "WORKER"} {
		raw := os.Getenv("CHEESETRAP_TEST_REPORTING_" + role + "_URL")
		if raw == "" {
			t.Fatal("isolated reporting credentials required")
		}
		p, err := store.NewPool(ctx, raw)
		if err != nil {
			t.Fatal(err)
		}
		defer p.Close()
		pools[role] = p
	}
	owner, collector, worker := pools["MIGRATION"], pools["COLLECTOR"], pools["WORKER"]
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := owner.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec("INSERT INTO cheesetrap.sensors(sensor_id,name,engine) VALUES('10000000-0000-4000-8000-000000000301','window-fixture','cowrie')")
	exec("INSERT INTO cheesetrap.file_generations(file_generation_id,sensor_id,path,device,inode) VALUES('20000000-0000-4000-8000-000000000301','10000000-0000-4000-8000-000000000301','/fixture/events',1,1)")
	end := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	var id string
	if err := owner.QueryRow(ctx, "INSERT INTO cheesetrap.report_windows(start_at,end_at,settings_version) VALUES($1,$2,1) RETURNING window_id", end.Add(-24*time.Hour), end).Scan(&id); err != nil {
		t.Fatal(err)
	}
	// Commit order is tested with actual uncommitted evidence and cursor changes.
	tx, err := collector.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if _, err = tx.Exec(ctx, "SELECT ingested_seq FROM cheesetrap.processing_cursors WHERE singleton FOR UPDATE"); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `INSERT INTO cheesetrap.events(sensor_id,file_generation_id,byte_offset,ingestion_seq,schema_version,engine,observed_at,ingested_at,service,event_type,raw_hash) VALUES('10000000-0000-4000-8000-000000000301','20000000-0000-4000-8000-000000000301',1,1,1,'cowrie',$1,$2,'ssh','session.connect',repeat('a',64))`, end.Add(-48*time.Hour), end.Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, "UPDATE cheesetrap.processing_cursors SET ingested_seq=1"); err != nil {
		t.Fatal(err)
	}
	type sealResult struct {
		ready bool
		err   error
	}
	done := make(chan sealResult, 1)
	go func() { ready, err := SealWindow(ctx, worker, id); done <- sealResult{ready, err} }()
	select {
	case <-done:
		t.Fatal("seal bypassed collector transaction with pending evidence")
	case <-time.After(150 * time.Millisecond):
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	result := <-done
	if result.err != nil {
		t.Fatal(result.err)
	}
	if result.ready {
		t.Fatal("window finalized before continuous detection completion")
	}
	var state string
	var seq int64
	if err = owner.QueryRow(ctx, "SELECT state,sealed_seq FROM cheesetrap.report_windows WHERE window_id=$1", id).Scan(&state, &seq); err != nil || state != "sealed" || seq != 1 {
		t.Fatalf("late commit missing from sealed watermark: state=%s seq=%d err=%v", state, seq, err)
	}
	// Late observed evidence ingested at/after the exact boundary is next-window
	// input, even if it carries a much older observed_at timestamp.
	exec(`INSERT INTO cheesetrap.events(sensor_id,file_generation_id,byte_offset,ingestion_seq,schema_version,engine,observed_at,ingested_at,service,event_type,raw_hash) SELECT sensor_id,file_generation_id,n,n,1,engine,observed_at,$1::timestamptz+(n-2)*interval '1 second',service,event_type,raw_hash FROM cheesetrap.events CROSS JOIN generate_series(2,3)n WHERE ingestion_seq=1`, end)
	exec("UPDATE cheesetrap.processing_cursors SET ingested_seq=3")
	if ready, err := SealWindow(ctx, worker, id); err != nil || ready {
		t.Fatal("later events bypassed detection backlog")
	}
	if _, err = detection.ProcessBatch(ctx, worker, 1); err != nil {
		t.Fatal(err)
	}
	if ready, err := SealWindow(ctx, worker, id); err != nil || !ready {
		t.Fatal("continuous detection completion did not release window", err)
	}
	var before, after string
	if err = owner.QueryRow(ctx, "SELECT row_to_json(w)::text FROM cheesetrap.report_windows w WHERE window_id=$1", id).Scan(&before); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 2 {
		wg.Go(func() {
			if ready, err := SealWindow(ctx, worker, id); err != nil || !ready {
				t.Error("duplicate seal changed readiness", err)
			}
		})
	}
	wg.Wait()
	if err = owner.QueryRow(ctx, "SELECT row_to_json(w)::text FROM cheesetrap.report_windows w WHERE window_id=$1", id).Scan(&after); err != nil || before != after {
		t.Fatal("duplicate seal mutated immutable window")
	}
	if _, err = worker.Exec(ctx, "UPDATE cheesetrap.report_windows SET sealed_seq=2 WHERE window_id=$1", id); err == nil {
		t.Fatal("sealed watermark is mutable")
	}
	// Delayed reconciliation excludes later events already committed before seal.
	var old string
	if err = owner.QueryRow(ctx, "INSERT INTO cheesetrap.report_windows(start_at,end_at,settings_version) VALUES($1,$2,1) RETURNING window_id", end.Add(-48*time.Hour), end.Add(-24*time.Hour)).Scan(&old); err != nil {
		t.Fatal(err)
	}
	if ready, err := SealWindow(ctx, worker, old); err != nil || !ready {
		t.Fatal("earlier empty interval must not wait for later-window events")
	}
	if err = owner.QueryRow(ctx, "SELECT sealed_seq FROM cheesetrap.report_windows WHERE window_id=$1", old).Scan(&seq); err != nil || seq != 0 {
		t.Fatal("seal used unfiltered global ingestion watermark")
	}
	if _, err = detection.ProcessBatch(ctx, worker, 100); err != nil {
		t.Fatal(err)
	}
	var empty string
	if err = owner.QueryRow(ctx, "INSERT INTO cheesetrap.report_windows(start_at,end_at,settings_version) VALUES($1,$2,1) RETURNING window_id", end.Add(24*time.Hour), end.Add(48*time.Hour)).Scan(&empty); err != nil {
		t.Fatal(err)
	}
	exec(`CREATE FUNCTION cheesetrap.test_window_interruption() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.state='ready' THEN RAISE EXCEPTION 'injected'; END IF; RETURN NEW; END $$; CREATE TRIGGER test_window_interruption BEFORE UPDATE ON cheesetrap.report_windows FOR EACH ROW EXECUTE FUNCTION cheesetrap.test_window_interruption()`)
	if _, err = SealWindow(ctx, worker, empty); err == nil {
		t.Fatal("interrupted window transaction succeeded")
	}
	if err = owner.QueryRow(ctx, "SELECT state FROM cheesetrap.report_windows WHERE window_id=$1", empty).Scan(&state); err != nil || state != "open" {
		t.Fatal("interrupted seal left partial state")
	}
	exec("DROP TRIGGER test_window_interruption ON cheesetrap.report_windows; DROP FUNCTION cheesetrap.test_window_interruption()")
	if ready, err := SealWindow(ctx, worker, empty); err != nil || !ready {
		t.Fatal("empty completed window did not become ready", err)
	}
	// The stable reporting query includes only detection triggers ingested in
	// this half-open window; observed_at may be from an earlier date.
	exec(`INSERT INTO cheesetrap.detection_results(rule_id,rule_version,processing_event_id,processing_ingestion_seq,source_ip,window_start,window_end,evidence_hash,evidence_count,evidence_eligible,auto_approval_allowed,explanation) SELECT 'SSH-REPEAT','1',event_id,ingestion_seq,'198.51.100.30',observed_at,observed_at,repeat('d',64),1,false,false,'{}' FROM cheesetrap.events`)
	var wid pgtype.UUID
	_ = wid.Scan(id)
	results, err := db.New(worker).ListWindowDetections(ctx, wid)
	if err != nil || len(results) != 1 || results[0].ProcessingIngestionSeq != 1 {
		t.Fatal("unstable window detection membership", err)
	}
	// Execute the production sqlc clock query used by CommitBatch, not a duplicate
	// formula, against an artificial sealed floor ahead of wall time.
	exec("UPDATE cheesetrap.processing_cursors SET sealed_before=clock_timestamp()+interval '1 day'")
	var floor time.Time
	if err = owner.QueryRow(ctx, "SELECT sealed_before FROM cheesetrap.processing_cursors").Scan(&floor); err != nil {
		t.Fatal(err)
	}
	at, err := db.New(collector).CommitClock(ctx)
	if err != nil || at.Time.Before(floor) {
		t.Fatal("production collector clock bypassed sealed floor")
	}
	change, err := ChangeSchedule(ctx, worker, "UTC", 1)
	if err != nil || !change.EffectiveFrom.Time.After(floor) {
		t.Fatal("clock rollback backdated schedule change", err)
	}
	var future string
	if err = owner.QueryRow(ctx, "INSERT INTO cheesetrap.report_windows(start_at,end_at,settings_version) VALUES(clock_timestamp()+interval '2 day',clock_timestamp()+interval '3 day',1) RETURNING window_id").Scan(&future); err != nil {
		t.Fatal(err)
	}
	if ready, err := SealWindow(ctx, worker, future); err != nil || ready {
		t.Fatal("future window finalized")
	}
}
