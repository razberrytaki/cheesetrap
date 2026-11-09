//go:build integration

package retention

import (
	"cheesetrap/internal/store"
	"context"
	"fmt"
	"github.com/jackc/pgx/v5/pgxpool"
	"os"
	"testing"
	"time"
)

func TestRetentionDatabase(t *testing.T) {
	ctx := context.Background()
	pools := map[string]*pgxpool.Pool{}
	for _, role := range []string{"MIGRATION", "WORKER", "API", "COLLECTOR"} {
		p, e := store.NewPool(ctx, os.Getenv("CHEESETRAP_TEST_RETENTION_"+role+"_URL"))
		if e != nil {
			t.Fatal(e)
		}
		defer p.Close()
		pools[role] = p
	}
	owner, worker := pools["MIGRATION"], pools["WORKER"]
	exec := func(q string, args ...any) {
		t.Helper()
		if _, e := owner.Exec(ctx, q, args...); e != nil {
			t.Fatal(e)
		}
	}
	now := time.Now().UTC()
	old := now.Add(-31 * 24 * time.Hour)
	exec(`INSERT INTO cheesetrap.sensors(sensor_id,name,engine) VALUES('10000000-0000-4000-8000-000000000701','retention','cowrie')`)
	exec(`INSERT INTO cheesetrap.collection_gap_incidents(sensor_id,started_at,observed_through,causes,gap_count) VALUES('10000000-0000-4000-8000-000000000701','2000-01-01','2000-01-02',ARRAY['legacy'],7)`)
	exec(`INSERT INTO cheesetrap.file_generations(file_generation_id,sensor_id,path,device,inode) VALUES('20000000-0000-4000-8000-000000000701','10000000-0000-4000-8000-000000000701','/fixture',1,1)`)
	exec(`INSERT INTO cheesetrap.events(sensor_id,file_generation_id,byte_offset,ingestion_seq,schema_version,engine,ingested_at,service,event_type,raw_hash) SELECT '10000000-0000-4000-8000-000000000701','20000000-0000-4000-8000-000000000701',n,n,1,'cowrie',$1,'ssh','test',repeat('a',64) FROM generate_series(1,5)n`, old)
	exec(`UPDATE cheesetrap.processing_cursors SET ingested_seq=5,detected_seq=3,sealed_before=$1`, now)
	exec(`INSERT INTO cheesetrap.detection_completions(event_id,ingestion_seq,rule_set_version) SELECT event_id,ingestion_seq,'v1' FROM cheesetrap.events WHERE ingestion_seq<=3`)
	p, e := Cleanup(ctx, worker, now, 2)
	if e != nil {
		t.Fatal(e)
	}
	if p.Deleted > 10 {
		t.Fatal("batch not bounded", p)
	}
	for i := 0; i < 4; i++ {
		if _, e = Cleanup(ctx, worker, now, 2); e != nil {
			t.Fatal(e)
		}
	}
	var remaining int
	if e = owner.QueryRow(ctx, `SELECT count(*) FROM cheesetrap.events`).Scan(&remaining); e != nil || remaining != 2 {
		t.Fatal("unprocessed evidence lost or expired retained", remaining, e)
	}
	if p, e = Cleanup(ctx, worker, now, 2); e != nil || p.ProtectedEvents != 2 {
		t.Fatal("backlog", p, e)
	}

	t.Run("terminal_history_and_jobs", func(t *testing.T) {
		exec(`INSERT INTO cheesetrap.report_windows(window_id,start_at,end_at,settings_version) VALUES('30000000-0000-4000-8000-000000000701',$1,$2,1)`, now.Add(-300*24*time.Hour), now.Add(-299*24*time.Hour))
		states := []string{"sent", "sent", "unknown", "closed_unconfirmed", "held"}
		ids := []string{}
		for i, state := range states {
			tx, err := owner.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			var id, rev string
			if err = tx.QueryRow(ctx, `SELECT gen_random_uuid()::text,gen_random_uuid()::text`).Scan(&id, &rev); err != nil {
				t.Fatal(err)
			}
			ids = append(ids, id)
			changed := now.Add(-181 * 24 * time.Hour)
			if i == 1 {
				changed = now.Add(-179 * 24 * time.Hour)
			}
			if _, err = tx.Exec(ctx, `INSERT INTO cheesetrap.reports(report_id,window_id,source_ip,version,current_revision_id,state,last_changed_at,delivery_uncertain) VALUES($1,'30000000-0000-4000-8000-000000000701',$2,1,$3,$4,$5,$6)`, id, fmt.Sprintf("8.8.8.%d", i+1), rev, state, changed, state == "unknown" || state == "closed_unconfirmed"); err != nil {
				t.Fatal(err)
			}
			if _, err = tx.Exec(ctx, `INSERT INTO cheesetrap.report_revisions(revision_id,report_id,version,snapshot,subject,body,recipient,reply_to,hold_reasons,state,auto_approval_allowed,body_edited,content_digest) VALUES($1,$2,1,'{}','subject','body','abuse@example.org','operator@example.org','{}','needs_review',false,false,repeat('a',64))`, rev, id); err != nil {
				t.Fatal(err)
			}
			if _, err = tx.Exec(ctx, `INSERT INTO cheesetrap.report_evidence(event_id,report_id,snapshot) SELECT gen_random_uuid(),$1,'{}' FROM generate_series(1,5)`, id); err != nil {
				t.Fatal(err)
			}
			if err = tx.Commit(ctx); err != nil {
				t.Fatal(err)
			}
		}

		// Two refresh records share an obsolete revision. A one-row batch must
		// retain that revision until BOTH referencing rows have been removed.
		exec(`INSERT INTO cheesetrap.admins(username,password_hash) VALUES('retention-admin','fixture')`)
		exec(`INSERT INTO cheesetrap.report_revisions(revision_id,report_id,version,snapshot,subject,body,recipient,reply_to,hold_reasons,state,auto_approval_allowed,body_edited,content_digest) VALUES('50000000-0000-4000-8000-000000000701',$1,2,'{}','old','old','abuse@example.org','operator@example.org','{}','needs_review',false,false,repeat('c',64))`, ids[0])
		exec(`INSERT INTO cheesetrap.contact_refresh_requests(report_id,expected_version,revision_id,settings_version,admin_id,status,result_revision_id,completed_at) SELECT $1,1,'50000000-0000-4000-8000-000000000701',1,admin_id,'completed','50000000-0000-4000-8000-000000000701',clock_timestamp() FROM cheesetrap.admins CROSS JOIN generate_series(1,2)`, ids[0])
		exec(`INSERT INTO cheesetrap_river.river_job(kind,args,queue,state,finalized_at,created_at) VALUES('retention_fixture','{}','retention','completed',$1,$2),('retention_fixture','{}','retention','completed',$3,$2),('retention_fixture','{}','retention','available',NULL,$2)`, now.Add(-8*24*time.Hour), now.Add(-10*24*time.Hour), now.Add(-6*24*time.Hour))
		if _, err := Cleanup(ctx, worker, now, 1); err != nil {
			t.Fatal(err)
		}
		var copies int
		owner.QueryRow(ctx, `SELECT count(*) FROM cheesetrap.report_evidence WHERE report_id=$1`, ids[0]).Scan(&copies)
		if copies != 4 {
			t.Fatal("child batch unbounded", copies)
		}
		for i := 0; i < 10; i++ {
			if _, err := Cleanup(ctx, worker, now, 2); err != nil {
				t.Fatal(err)
			}
		}
		for i, id := range ids {
			var exists bool
			if err := owner.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM cheesetrap.reports WHERE report_id=$1)`, id).Scan(&exists); err != nil {
				t.Fatal(err)
			}
			if exists != (i != 0 && i != 3) {
				t.Fatalf("report %s state %s exists %v", id, states[i], exists)
			}
		}

		// Aggregation backlog must survive until its evidence is copied, even after
		// detection and window sealing have advanced past it.
		exec(`INSERT INTO cheesetrap.events(sensor_id,file_generation_id,byte_offset,ingestion_seq,schema_version,engine,ingested_at,service,event_type,raw_hash) SELECT '10000000-0000-4000-8000-000000000701','20000000-0000-4000-8000-000000000701',n,n,1,'cowrie',$1,'ssh','test',repeat('a',64) FROM generate_series(6,7)n`, old)
		exec(`UPDATE cheesetrap.processing_cursors SET ingested_seq=7,detected_seq=7`)
		exec(`INSERT INTO cheesetrap.detection_completions(event_id,ingestion_seq,rule_set_version) SELECT event_id,ingestion_seq,'v1' FROM cheesetrap.events WHERE ingestion_seq>=6`)
		exec(`INSERT INTO cheesetrap.detection_results(detection_id,rule_id,rule_version,processing_event_id,processing_ingestion_seq,source_ip,window_start,window_end,evidence_hash,evidence_count,evidence_eligible,auto_approval_allowed,explanation) SELECT '40000000-0000-4000-8000-000000000701','SSH-REPEAT','1',event_id,ingestion_seq,'8.8.8.5',$1,$1,repeat('b',64),1,false,false,'{}' FROM cheesetrap.events WHERE ingestion_seq=6`, old)
		exec(`INSERT INTO cheesetrap.detection_evidence(detection_id,event_id) SELECT '40000000-0000-4000-8000-000000000701',event_id FROM cheesetrap.events WHERE ingestion_seq=7`)
		exec(`INSERT INTO cheesetrap.report_windows(window_id,start_at,end_at,settings_version,state,sealed_seq,sealed_at,ready_at) VALUES('30000000-0000-4000-8000-000000000702',$1,$2,1,'ready',7,$2,$2)`, old.Add(-time.Hour), old.Add(time.Hour))
		exec(`INSERT INTO cheesetrap.report_window_completions(window_id) VALUES('30000000-0000-4000-8000-000000000702')`)
		if _, err := Cleanup(ctx, worker, now, 100); err != nil {
			t.Fatal(err)
		}
		var evidenceCount int
		owner.QueryRow(ctx, `SELECT count(*) FROM cheesetrap.events WHERE ingestion_seq>=6`).Scan(&evidenceCount)
		if evidenceCount != 2 {
			t.Fatal("uncopied evidence lost", evidenceCount)
		}
		exec(`INSERT INTO cheesetrap.report_evidence(event_id,report_id,snapshot) SELECT event_id,$1,'{}' FROM cheesetrap.events WHERE ingestion_seq=7`, ids[4])
		if _, err := Cleanup(ctx, worker, now, 100); err != nil {
			t.Fatal(err)
		}
		owner.QueryRow(ctx, `SELECT count(*) FROM cheesetrap.events WHERE ingestion_seq>=6`).Scan(&evidenceCount)
		if evidenceCount != 0 {
			t.Fatal("copied expired events retained", evidenceCount)
		}
		owner.QueryRow(ctx, `SELECT count(*) FROM cheesetrap.report_evidence WHERE report_id=$1`, ids[4]).Scan(&evidenceCount)
		if evidenceCount != 6 {
			t.Fatal("ongoing copies lost", evidenceCount)
		}
		var jobs int
		owner.QueryRow(ctx, `SELECT count(*) FROM cheesetrap_river.river_job WHERE kind='retention_fixture'`).Scan(&jobs)
		if jobs != 2 {
			t.Fatal("job retention", jobs)
		}
	})
	for _, role := range []string{"API", "COLLECTOR"} {
		if _, e = Cleanup(ctx, pools[role], now, 2); e == nil {
			t.Fatal("cleanup privilege", role)
		}
	}
	if _, e = worker.Exec(ctx, `DELETE FROM cheesetrap.events`); e == nil {
		t.Fatal("worker direct deletion")
	}
	if _, e = Cleanup(ctx, worker, now, 1001); e == nil {
		t.Fatal("unbounded cleanup")
	}
	var history bool
	if err := owner.QueryRow(ctx, `SELECT count(*)=1 AND bool_and(gap_count=7 AND started_at='2000-01-01'::timestamptz AND observed_through='2000-01-02'::timestamptz AND causes=ARRAY['legacy']) FROM cheesetrap.collection_gap_incidents WHERE sensor_id='10000000-0000-4000-8000-000000000701'`).Scan(&history); err != nil || !history {
		t.Fatal("retention erased dated gap history", err)
	}

}
