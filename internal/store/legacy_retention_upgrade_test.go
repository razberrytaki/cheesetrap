//go:build integration

package store_test

import (
	"cheesetrap/internal/store"
	"context"
	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
	"github.com/riverqueue/river/rivermigrate"
	"testing"
)

// Exercise the real pre-17 cleanup, which removes links without a state marker.
// Return a post-upgrade check so the existing populated v14 migration test also
// covers an interrupted legacy batch, alongside its untouched complete root.
func seedPartialLegacyRetention(t *testing.T, owner, worker *pgx.Conn) func(*testing.T) {
	t.Helper()
	ctx := context.Background()
	pool, e := store.NewPool(ctx, owner.Config().ConnString())
	if e != nil {
		t.Fatal(e)
	}
	defer pool.Close()
	river, e := rivermigrate.New(riverpgxv5.New(pool), &rivermigrate.Config{Schema: "cheesetrap_river"})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = river.Migrate(ctx, rivermigrate.DirectionUp, &rivermigrate.MigrateOpts{TargetVersion: 8}); e != nil {
		t.Fatal(e)
	}
	exec := func(c *pgx.Conn, q string) {
		t.Helper()
		if _, e := c.Exec(ctx, q); e != nil {
			t.Fatal(e)
		}
	}
	count := func(q string) int {
		t.Helper()
		var n int
		if e := owner.QueryRow(ctx, q).Scan(&n); e != nil {
			t.Fatal(e)
		}
		return n
	}
	exec(owner, `INSERT INTO cheesetrap.events(event_id,sensor_id,file_generation_id,byte_offset,ingestion_seq,schema_version,engine,source_ip,destination_ip,destination_port,service,event_type,attributes,raw_hash,ingested_at)
 SELECT ('00000000-0000-0000-0000-'||lpad(n::text,12,'0'))::uuid,'10000000-0000-0000-0000-000000000015','20000000-0000-0000-0000-000000000015',n,n,1,'cowrie','1.1.1.1','8.8.8.8',22,'ssh','login.failed','{}',repeat('a',64),now()-interval '40 days' FROM generate_series(131,134)n;
 UPDATE cheesetrap.processing_cursors SET ingested_seq=134,detected_seq=134,sealed_before=now();
 INSERT INTO cheesetrap.detection_completions(ingestion_seq,event_id,rule_set_version) SELECT ingestion_seq,event_id,'1' FROM cheesetrap.events WHERE ingestion_seq>=131;
 INSERT INTO cheesetrap.report_windows(window_id,start_at,end_at,settings_version,state,sealed_seq,sealed_at,ready_at) VALUES('70000000-0000-0000-0000-000000000017',now()-interval '41 days',now()-interval '39 days',1,'ready',134,now(),now());
 INSERT INTO cheesetrap.report_window_completions(window_id) VALUES('70000000-0000-0000-0000-000000000017');`)
	exec(owner, `BEGIN;
 INSERT INTO cheesetrap.reports(report_id,window_id,source_ip,version,current_revision_id,state,last_changed_at) VALUES('80000000-0000-0000-0000-000000000017','70000000-0000-0000-0000-000000000017','1.1.1.1',1,'90000000-0000-0000-0000-000000000017','held',now());
 INSERT INTO cheesetrap.report_revisions(revision_id,report_id,version,snapshot,subject,body,recipient,reply_to,hold_reasons,state,auto_approval_allowed,body_edited,content_digest) VALUES('90000000-0000-0000-0000-000000000017','80000000-0000-0000-0000-000000000017',1,'{}','s','b','a@example.org','b@example.org','{}','needs_review',false,false,repeat('a',64));
 INSERT INTO cheesetrap.report_evidence(event_id,report_id,snapshot) SELECT event_id,'80000000-0000-0000-0000-000000000017','{}' FROM cheesetrap.events WHERE ingestion_seq>=131;
 INSERT INTO cheesetrap.detection_results(detection_id,rule_id,rule_version,processing_event_id,processing_ingestion_seq,source_ip,window_start,window_end,evidence_hash,evidence_count,evidence_eligible,auto_approval_allowed,explanation) VALUES('60000000-0000-0000-0000-000000000017','SSH-REPEAT','upgrade','00000000-0000-0000-0000-000000000134',134,'1.1.1.1',now()-interval '40 days',now()-interval '40 days',repeat('a',64),4,false,false,'{}');
 INSERT INTO cheesetrap.detection_evidence SELECT '60000000-0000-0000-0000-000000000017',event_id FROM cheesetrap.events WHERE ingestion_seq>=131;
 COMMIT;`)
	exec(worker, `SELECT * FROM cheesetrap.retention_cleanup(now(),1)`)
	if count(`SELECT count(*) FROM cheesetrap.detection_evidence WHERE detection_id='60000000-0000-0000-0000-000000000017'`) != 3 {
		t.Fatal("old cleanup did not leave partial legacy root")
	}
	var before string
	snapshot := `SELECT (to_jsonb(d)-'evidence_representation'-'evidence_state')::text FROM cheesetrap.detection_results d WHERE detection_id='60000000-0000-0000-0000-000000000017'`
	if e := owner.QueryRow(ctx, snapshot).Scan(&before); e != nil {
		t.Fatal(e)
	}
	return func(t *testing.T) {
		t.Helper()
		var state, after string
		if e := owner.QueryRow(ctx, `SELECT evidence_state FROM cheesetrap.detection_results WHERE detection_id='60000000-0000-0000-0000-000000000017'`).Scan(&state); e != nil || state != "retiring" {
			t.Fatal("pre-17 partial legacy root must migrate to retiring", state, e)
		}
		if e := owner.QueryRow(ctx, snapshot).Scan(&after); e != nil || before != after {
			t.Fatal("upgrade changed immutable legacy proof", e)
		}
		if count(`SELECT count(*) FROM cheesetrap.detection_evidence_membership WHERE detection_id='60000000-0000-0000-0000-000000000017'`) != 0 {
			t.Fatal("migrated partial legacy root exposed")
		}
		if _, e := worker.Exec(ctx, `SELECT cheesetrap.store_detection_chunks('60000000-0000-0000-0000-000000000017',64,ARRAY[]::uuid[])`); e == nil || e.Error() != "ERROR: retired_result (SQLSTATE 23514)" {
			t.Fatal("partial legacy retry not fail-closed", e)
		}
		if count(`SELECT count(*) FROM cheesetrap.report_evidence WHERE report_id='80000000-0000-0000-0000-000000000017'`) != 4 {
			t.Fatal("legacy report copies changed by upgrade")
		}
		for i := 0; i < 5; i++ {
			exec(worker, `SELECT * FROM cheesetrap.retention_cleanup(now(),1)`)
		}
		if count(`SELECT count(*) FROM cheesetrap.detection_results WHERE detection_id='60000000-0000-0000-0000-000000000017'`)+count(`SELECT count(*) FROM cheesetrap.events WHERE ingestion_seq>=131`) != 0 {
			t.Fatal("migrated partial legacy cleanup did not converge")
		}
		if count(`SELECT count(*) FROM cheesetrap.report_evidence WHERE report_id='80000000-0000-0000-0000-000000000017'`) != 4 {
			t.Fatal("live report copies lost during recovery")
		}
	}
}
