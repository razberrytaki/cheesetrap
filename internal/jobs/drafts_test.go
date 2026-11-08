//go:build integration

package jobs

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"cheesetrap/internal/enrichment"
	"cheesetrap/internal/reporting"
	"cheesetrap/internal/store"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestDraftRuntime(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	pools := map[string]*pgxpool.Pool{}
	for _, role := range []string{"MIGRATION", "WORKER", "API"} {
		p, err := store.NewPool(ctx, os.Getenv("CHEESETRAP_TEST_DRAFT_RUNTIME_"+role+"_URL"))
		if err != nil {
			t.Fatal(err)
		}
		defer p.Close()
		pools[role] = p
	}
	owner, worker := pools["MIGRATION"], pools["WORKER"]
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := owner.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO cheesetrap.sensors(sensor_id,name,engine,public_ip,public_port) VALUES('10000000-0000-4000-8000-000000000405','draft-runtime','cowrie','8.8.8.8',2222)`)
	exec(`INSERT INTO cheesetrap.file_generations(file_generation_id,sensor_id,path,device,inode) VALUES('20000000-0000-4000-8000-000000000405','10000000-0000-4000-8000-000000000405','/fixture',1,1)`)
	exec(`INSERT INTO cheesetrap.events(sensor_id,file_generation_id,byte_offset,ingestion_seq,schema_version,engine,observed_at,ingested_at,source_ip,destination_ip,destination_port,service,event_type,quality_flags,raw_hash) SELECT '10000000-0000-4000-8000-000000000405','20000000-0000-4000-8000-000000000405',n,n,1,'cowrie',clock_timestamp()-interval '1 day'+n*interval '1 second',clock_timestamp()-interval '1 day','1.1.1.1','8.8.8.8',2222,'ssh','cowrie.login.failed',ARRAY['credentials_redacted'],repeat('a',64) FROM generate_series(1,10)n`)
	exec("UPDATE cheesetrap.processing_cursors SET ingested_seq=10")
	if err := reporting.SetReplyTo(ctx, pools["API"], "operator@example.org"); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	source := enrichment.Source{Role: "abuse", Method: "rdap", SourceURL: "https://rdap.example.net/ip/1.1.1.1", NetworkStart: "1.1.1.0", NetworkEnd: "1.1.1.255"}
	contact := enrichment.Result{SchemaVersion: 1, Address: "1.1.1.1", LookupSucceeded: true, QueriedAt: now, ExpiresAt: now.Add(time.Hour), Candidates: []enrichment.Contact{{Email: "abuse@example.net", Role: "abuse", Sources: []enrichment.Source{source}}}}
	data, _ := json.Marshal(contact)
	exec("INSERT INTO cheesetrap.enrichment_cache(address,result,queried_at,expires_at) VALUES('1.1.1.1',$1,$2,$3)", data, now, now.Add(time.Hour))
	exec(`INSERT INTO cheesetrap.admins(username,password_hash) VALUES('legacy-automatic','test-only')`)
	exec(`UPDATE cheesetrap.automatic_policy SET enabled=true,actor_id=(SELECT admin_id FROM cheesetrap.admins LIMIT 1)`)
	exec(`UPDATE cheesetrap.settings SET value=value || '{"automatic_mode":true,"delivery_limits":{"daily":100,"recipient_daily":20}}'::jsonb WHERE key='review_policy'`)
	exec(`INSERT INTO cheesetrap_river.river_job(kind,args,queue,max_attempts) VALUES('deliver_report','{"approval_id":"00000000-0000-4000-8000-000000000001"}','delivery',25),('smtp_test','{"test_id":"00000000-0000-4000-8000-000000000001"}','delivery',25)`)
	runCtx, stop := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- Run(runCtx, os.Getenv("CHEESETRAP_TEST_DRAFT_RUNTIME_WORKER_URL"), 5*time.Second) }()
	defer func() {
		stop()
		select {
		case <-done:
		case <-time.After(6 * time.Second):
			t.Error("runtime did not stop")
		}
	}()
	deadline := time.NewTimer(15 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case err := <-done:
			t.Fatal("worker stopped", err)
		case <-deadline.C:
			t.Fatal("ready windows never reached report revisions")
		case <-ticker.C:
			var count int
			if err := owner.QueryRow(ctx, "SELECT count(*) FROM cheesetrap.report_revisions WHERE state='needs_review' AND NOT auto_approval_allowed AND recipient='abuse@example.net'").Scan(&count); err != nil {
				t.Fatal(err)
			}
			if count == 1 {
				goto complete
			}
		}
	}
complete:
	var outbound, attempted int
	if err := owner.QueryRow(ctx, `SELECT (SELECT count(*) FROM cheesetrap.approvals)+(SELECT count(*) FROM cheesetrap.delivery_attempts)+(SELECT count(*) FROM cheesetrap.smtp_tests),(SELECT coalesce(sum(attempt),0) FROM cheesetrap_river.river_job WHERE kind IN ('deliver_report','smtp_test'))`).Scan(&outbound, &attempted); err != nil || outbound != 0 || attempted != 0 {
		t.Fatal("legacy settings or jobs revived sending", outbound, attempted, err)
	}
	stop()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	done <- nil
	client, err := NewClient(worker)
	if err != nil {
		t.Fatal(err)
	}
	// Remove a job at the empty-window completion boundary; durable ready state
	// must repair it even after every sealing job has already succeeded.
	exec("TRUNCATE cheesetrap.report_window_completions")
	exec("DELETE FROM cheesetrap_river.river_job WHERE kind='draft_reports'")
	if _, err = Reconcile(ctx, worker, client); err != nil {
		t.Fatal(err)
	}
	var unfinished, active int
	if err = owner.QueryRow(ctx, "SELECT count(*) FROM cheesetrap.report_windows w WHERE state='ready' AND NOT EXISTS(SELECT 1 FROM cheesetrap.report_window_completions c WHERE c.window_id=w.window_id)").Scan(&unfinished); err != nil {
		t.Fatal(err)
	}
	if err = owner.QueryRow(ctx, "SELECT count(*) FROM cheesetrap_river.river_job WHERE kind='draft_reports' AND state='available'").Scan(&active); err != nil {
		t.Fatal(err)
	}
	if unfinished != 1 || active != 1 {
		t.Fatal("lost draft job not repaired")
	}
}
