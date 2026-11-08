//go:build integration

package retention

import (
	"cheesetrap/internal/store"
	"context"
	"github.com/jackc/pgx/v5"
	"os"
	"testing"
	"time"
)

func TestChunkRetentionDatabase(t *testing.T) {
	ctx := context.Background()
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
	exec := func(q string, args ...any) {
		t.Helper()
		if _, e := owner.Exec(ctx, q, args...); e != nil {
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
	now := time.Now().UTC()
	old := now.Add(-40 * 24 * time.Hour)
	exec(`INSERT INTO cheesetrap.sensors(sensor_id,name,engine) VALUES('10000000-0000-4000-8000-000000000801','chunks-retention','cowrie'); INSERT INTO cheesetrap.file_generations(file_generation_id,sensor_id,path,device,inode) VALUES('20000000-0000-4000-8000-000000000801','10000000-0000-4000-8000-000000000801','/chunks',1,1)`)
	exec(`INSERT INTO cheesetrap.events(sensor_id,file_generation_id,byte_offset,ingestion_seq,schema_version,engine,ingested_at,service,event_type,raw_hash) SELECT '10000000-0000-4000-8000-000000000801','20000000-0000-4000-8000-000000000801',n,n,1,'cowrie',$1,'ssh','test',repeat('a',64) FROM generate_series(1001,1130)n`, old)
	exec(`INSERT INTO cheesetrap.detection_completions(event_id,ingestion_seq,rule_set_version) SELECT event_id,ingestion_seq,'1' FROM cheesetrap.events WHERE ingestion_seq BETWEEN 1001 AND 1130`)
	exec(`UPDATE cheesetrap.processing_cursors SET ingested_seq=1130,detected_seq=1130,sealed_before=$1`, now)
	exec(`INSERT INTO cheesetrap.report_windows(window_id,start_at,end_at,settings_version,state,sealed_seq,sealed_at,ready_at) VALUES('30000000-0000-4000-8000-000000000801',$1,$2,1,'ready',1130,$2,$2);`, old.Add(-time.Hour), old.Add(time.Hour))
	exec(`INSERT INTO cheesetrap.report_window_completions(window_id) VALUES('30000000-0000-4000-8000-000000000801')`)
	tx, e := owner.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	_, e = tx.Exec(ctx, `INSERT INTO cheesetrap.reports(report_id,window_id,source_ip,version,current_revision_id,state,last_changed_at) VALUES('40000000-0000-4000-8000-000000000801','30000000-0000-4000-8000-000000000801','8.8.4.4',1,'50000000-0000-4000-8000-000000000801','held',now()); INSERT INTO cheesetrap.report_revisions(revision_id,report_id,version,snapshot,subject,body,recipient,reply_to,hold_reasons,state,auto_approval_allowed,body_edited,content_digest) VALUES('50000000-0000-4000-8000-000000000801','40000000-0000-4000-8000-000000000801',1,'{}','s','b','a@example.org','b@example.org','{}','needs_review',false,false,repeat('a',64));`)
	if e != nil {
		t.Fatal(e)
	}
	if e = tx.Commit(ctx); e != nil {
		t.Fatal(e)
	}
	create := func(id, rule string, retire ...bool) {
		t.Helper()
		var digest string
		if e := owner.QueryRow(ctx, `SELECT cheesetrap.evidence_set_hash(array_agg(event_id ORDER BY event_id)) FROM cheesetrap.events WHERE ingestion_seq BETWEEN 1001 AND 1130`).Scan(&digest); e != nil {
			t.Fatal(e)
		}
		tx, e := worker.Begin(ctx)
		if e != nil {
			t.Fatal(e)
		}
		defer tx.Rollback(ctx)
		_, e = tx.Exec(ctx, `INSERT INTO cheesetrap.detection_results(detection_id,rule_id,rule_version,processing_event_id,processing_ingestion_seq,source_ip,window_start,window_end,evidence_hash,evidence_count,evidence_eligible,auto_approval_allowed,explanation,evidence_representation) SELECT $1,$2,'1',event_id,ingestion_seq,'8.8.4.4',ingested_at,ingested_at,$3,130,false,false,'{}','chunks-v1' FROM cheesetrap.events WHERE ingestion_seq=1130`, id, rule, digest)
		if e != nil {
			t.Fatal(e)
		}
		_, e = tx.Exec(ctx, `SELECT cheesetrap.store_detection_chunks($1,64,(SELECT array_agg(event_id ORDER BY event_id) FROM cheesetrap.events WHERE ingestion_seq BETWEEN 1001 AND 1130))`, id)
		if e != nil {
			t.Fatal(e)
		}
		if len(retire) > 0 {
			for i := 0; i < 3; i++ {
				if _, e = tx.Exec(ctx, `SELECT * FROM cheesetrap.retention_cleanup(now(),1)`); e != nil {
					t.Fatal(e)
				}
			}
			if _, e = tx.Exec(ctx, `SET CONSTRAINTS ALL IMMEDIATE`); e != nil {
				t.Fatal("controlled partial retirement rejected by deferred checks", e)
			}
			return // rollback: prove the permitted deferred state without changing fixture
		}
		if e = tx.Commit(ctx); e != nil {
			t.Fatal(e)
		}
	}
	a := "60000000-0000-4000-8000-000000000801"
	b := "60000000-0000-4000-8000-000000000802"
	create(a, "SSH-REPEAT")
	create(b, "WEB-REPEAT")
	cleanup := func() {
		t.Helper()
		if _, e := Cleanup(ctx, worker, now, 1); e != nil {
			t.Fatal(e)
		}
	}
	// Statement transition tables prove the actual DELETE cardinality, including
	// cascading mistakes, independently from the returned aggregate count.
	exec(`CREATE FUNCTION cheesetrap.test_retention_bound() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF (SELECT count(*) FROM removed)>1 THEN RAISE EXCEPTION 'unbounded_retention_delete'; END IF; RETURN NULL; END $$`)
	for _, table := range []string{"detection_evidence", "detection_evidence_chunks", "evidence_chunk_members", "evidence_chunks"} {
		exec("CREATE TRIGGER test_retention_bound AFTER DELETE ON cheesetrap." + table + " REFERENCING OLD TABLE AS removed FOR EACH STATEMENT EXECUTE FUNCTION cheesetrap.test_retention_bound()")
		defer owner.Exec(ctx, "DROP TRIGGER test_retention_bound ON cheesetrap."+table)
	}
	defer owner.Exec(ctx, "DROP FUNCTION cheesetrap.test_retention_bound() CASCADE")
	cleanup()
	if count(`SELECT count(*) FROM cheesetrap.detection_results WHERE evidence_state='active' AND detection_id::text LIKE '60000000%'`) != 2 {
		t.Fatal("uncopied root retired")
	}
	exec(`INSERT INTO cheesetrap.report_evidence(event_id,report_id,snapshot) SELECT event_id,'40000000-0000-4000-8000-000000000801','{}' FROM cheesetrap.events WHERE ingestion_seq BETWEEN 1001 AND 1130`)
	// Terminal history may expire, but copies required by an active root survive.
	exec(`ALTER TABLE cheesetrap.reports DISABLE TRIGGER USER; UPDATE cheesetrap.reports SET state='closed_unconfirmed',last_changed_at=now()-interval '181 days' WHERE report_id='40000000-0000-4000-8000-000000000801'; ALTER TABLE cheesetrap.reports ENABLE TRIGGER USER`)
	// Force a failure at the first reference DELETE: root mark must roll back.
	exec(`CREATE FUNCTION cheesetrap.test_retention_interrupt() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'interrupted_after_mark'; END $$; CREATE TRIGGER test_retention_interrupt BEFORE DELETE ON cheesetrap.detection_evidence_chunks FOR EACH STATEMENT EXECUTE FUNCTION cheesetrap.test_retention_interrupt()`)
	if _, e = Cleanup(ctx, worker, now, 1); e == nil {
		t.Fatal("interruption was ignored")
	}
	if count(`SELECT count(*) FROM cheesetrap.detection_results WHERE evidence_state='retiring'`) != 0 {
		t.Fatal("failed cleanup committed root mark")
	}
	exec(`DROP TRIGGER test_retention_interrupt ON cheesetrap.detection_evidence_chunks; DROP FUNCTION cheesetrap.test_retention_interrupt()`)
	// A committed mark-only phase is restartable, including a fresh caller.
	exec(`CREATE FUNCTION cheesetrap.test_mark_only() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NULL; END $$; CREATE TRIGGER test_mark_only BEFORE DELETE ON cheesetrap.detection_evidence_chunks FOR EACH ROW EXECUTE FUNCTION cheesetrap.test_mark_only()`)
	cleanup()
	if count(`SELECT count(*) FROM cheesetrap.detection_evidence_chunks r JOIN cheesetrap.detection_results d USING(detection_id) WHERE d.evidence_state='retiring'`) != 3 {
		t.Fatal("mark-only checkpoint missing")
	}
	exec(`DROP TRIGGER test_mark_only ON cheesetrap.detection_evidence_chunks; DROP FUNCTION cheesetrap.test_mark_only()`)
	cleanup()
	if count(`SELECT count(*) FROM cheesetrap.detection_results WHERE evidence_state='retiring'`) != 1 {
		t.Fatal("root not marked retiring before bounded reference deletion")
	}
	if count(`SELECT count(*) FROM cheesetrap.detection_evidence_membership WHERE detection_id IN (SELECT detection_id FROM cheesetrap.detection_results WHERE evidence_state='retiring')`) != 0 {
		t.Fatal("partial root exposed")
	}
	var retiring string
	if e = owner.QueryRow(ctx, `SELECT detection_id::text FROM cheesetrap.detection_results WHERE evidence_state='retiring'`).Scan(&retiring); e != nil {
		t.Fatal(e)
	}
	if _, e = worker.Exec(ctx, `SELECT cheesetrap.store_detection_chunks($1,64,(SELECT array_agg(event_id ORDER BY event_id) FROM cheesetrap.events WHERE ingestion_seq BETWEEN 1001 AND 1130))`, retiring); e == nil {
		t.Fatal("partial root retry accepted")
	}
	if count(`SELECT count(*) FROM cheesetrap.report_evidence WHERE report_id='40000000-0000-4000-8000-000000000801'`) != 130 {
		t.Fatal("terminal report copies lost while shared active root needs them")
	}
	if count(`SELECT count(*) FROM cheesetrap.evidence_chunk_members`) != 130 {
		t.Fatal("shared chunk collected")
	}
	exec(`UPDATE cheesetrap.processing_cursors SET sealed_before=$1`, old)
	for i := 0; i < 2; i++ {
		cleanup()
	}
	// Last-reference retirement and member deletion are atomic on failure.
	exec(`CREATE FUNCTION cheesetrap.test_chunk_interrupt() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'interrupted_after_chunk_retire'; END $$; CREATE TRIGGER test_chunk_interrupt BEFORE DELETE ON cheesetrap.evidence_chunk_members FOR EACH STATEMENT EXECUTE FUNCTION cheesetrap.test_chunk_interrupt()`)
	if _, e = Cleanup(ctx, worker, now, 1); e == nil {
		t.Fatal("chunk interruption ignored")
	}
	if count(`SELECT count(*) FROM cheesetrap.evidence_chunks WHERE retired`) != 0 {
		t.Fatal("failed chunk cleanup committed retirement")
	}
	exec(`DROP TRIGGER test_chunk_interrupt ON cheesetrap.evidence_chunk_members; DROP FUNCTION cheesetrap.test_chunk_interrupt()`)
	cleanup()
	if count(`SELECT count(*) FROM cheesetrap.evidence_chunk_members`) < 128 {
		t.Fatal("member deletion unbounded")
	}
	// All events stay behind the sealing boundary while a retired partial
	// chunk coexists with a newly written, identical complete chunk.
	if count(`SELECT count(*) FROM cheesetrap.evidence_chunks WHERE retired`) == 0 {
		t.Fatal("orphan was not retired")
	}
	// Cursor locking blocks both cleanup and writer against partial chunks.
	gate, e := owner.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = gate.Exec(ctx, `SELECT 1 FROM cheesetrap.processing_cursors FOR UPDATE`); e != nil {
		t.Fatal(e)
	}
	for _, query := range []string{`SELECT * FROM cheesetrap.retention_cleanup(now(),1)`, `SELECT cheesetrap.store_detection_chunks('60000000-0000-4000-8000-000000000802',64,ARRAY[]::uuid[])`} {
		conn, e := pgx.Connect(ctx, os.Getenv("CHEESETRAP_TEST_RETENTION_WORKER_URL"))
		if e != nil {
			t.Fatal(e)
		}
		timed, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
		_, e = conn.Exec(timed, query)
		blocked := timed.Err() == context.DeadlineExceeded
		cancel()
		conn.Close(ctx)
		if e == nil || !blocked {
			t.Fatal("cursor serialization bypassed")
		}
	}
	if e = gate.Rollback(ctx); e != nil {
		t.Fatal(e)
	}
	// The unchanged sealing boundary also counts orphan physical FK blockers.
	var protected int
	if e = owner.QueryRow(ctx, `SELECT protected_events FROM cheesetrap.retention_status`).Scan(&protected); e != nil || protected < 130 {
		t.Fatal("physical blockers missing", protected, e)
	}
	exec(`INSERT INTO cheesetrap.report_evidence(event_id,report_id,snapshot) SELECT event_id,'40000000-0000-4000-8000-000000000801','{}' FROM cheesetrap.events WHERE ingestion_seq BETWEEN 1001 AND 1130 ON CONFLICT DO NOTHING`)
	create("60000000-0000-4000-8000-000000000803", "SSH-REPEAT", true)
	create("60000000-0000-4000-8000-000000000803", "SSH-REPEAT")
	if count(`SELECT count(*) FROM cheesetrap.evidence_chunks a JOIN cheesetrap.evidence_chunks b USING(content_hash) WHERE a.retired AND NOT b.retired`) == 0 {
		t.Fatal("writer reused partial retired chunk")
	}
	if count(`SELECT count(*) FROM cheesetrap.detection_evidence_membership WHERE detection_id='60000000-0000-4000-8000-000000000803'`) != 130 {
		t.Fatal("replacement chunk incomplete")
	}
	exec(`UPDATE cheesetrap.processing_cursors SET sealed_before=$1`, now)
	checkedPhysical := false
	for i := 0; i < 300; i++ {
		cleanup()
		if !checkedPhysical && count(`SELECT count(*) FROM cheesetrap.detection_results WHERE detection_id::text LIKE '60000000%'`) == 0 && count(`SELECT count(*) FROM cheesetrap.evidence_chunk_members`) > 0 {
			physical := count(`SELECT count(DISTINCT event_id) FROM cheesetrap.evidence_chunk_members`)
			if count(`SELECT protected_events FROM cheesetrap.retention_status`) < physical {
				t.Fatal("unsealed orphan FK blockers missing from protected count")
			}
			checkedPhysical = true
		}
		if count(`SELECT count(*) FROM cheesetrap.evidence_chunks`) == 0 && count(`SELECT count(*) FROM cheesetrap.events WHERE ingestion_seq BETWEEN 1001 AND 1130`) == 0 {
			break
		}
	}
	if !checkedPhysical {
		t.Fatal("partial orphan state not observed")
	}
	if count(`SELECT count(*) FROM cheesetrap.detection_results WHERE detection_id::text LIKE '60000000%'`)+count(`SELECT count(*) FROM cheesetrap.evidence_chunks`)+count(`SELECT count(*) FROM cheesetrap.events WHERE ingestion_seq BETWEEN 1001 AND 1130`) != 0 {
		t.Fatal("resumed cleanup failed to converge")
	}
	if count(`SELECT count(*) FROM cheesetrap.report_evidence WHERE report_id='40000000-0000-4000-8000-000000000801'`) != 0 {
		t.Fatal("expired report copies retained after final root")
	}
}
