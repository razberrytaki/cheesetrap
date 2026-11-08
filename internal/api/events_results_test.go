//go:build integration

package api

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5"
)

func TestEventDetectionResults(t *testing.T) {
	f := newReviewFixtureDomain(t, "EVENTRESULT")
	owner, h, worker := f.owner, f.h, f.worker
	ctx := context.Background()
	t.Cleanup(func() {
		if _, err := owner.Exec(ctx, "DELETE FROM cheesetrap.report_windows WHERE window_id=$1", f.window); err != nil {
			t.Error(err)
		}
	})
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := owner.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	const sensor = "10000000-0000-4000-8000-000000000504"
	const generation = "20000000-0000-4000-8000-000000000504"
	const base int64 = 1000000000000000
	var window, report string
	var ingested, detected int64
	if err := owner.QueryRow(ctx, "SELECT ingested_seq,detected_seq FROM cheesetrap.processing_cursors").Scan(&ingested, &detected); err != nil {
		t.Fatal(err)
	}
	exec("INSERT INTO cheesetrap.sensors(sensor_id,name,engine) VALUES($1,'event-results','cowrie')", sensor)
	exec("INSERT INTO cheesetrap.file_generations(file_generation_id,sensor_id,path,device,inode) VALUES($1,$2,'/test/results',1,1)", generation, sensor)
	ids := make([]string, 7)
	for i := 1; i <= 6; i++ {
		ids[i] = fmt.Sprintf("30000000-0000-4000-8000-%012d", 5040+i)
		exec(`INSERT INTO cheesetrap.events(event_id,sensor_id,file_generation_id,byte_offset,ingestion_seq,schema_version,engine,observed_at,source_ip,service,event_type,attributes,raw_hash) VALUES($1,$2,$3,$4,$5,1,'cowrie','2000-01-01','192.0.2.204','ssh','result.test','{}',repeat('a',64))`, ids[i], sensor, generation, i, base+int64(i))
	}
	exec("UPDATE cheesetrap.processing_cursors SET ingested_seq=$1,detected_seq=$2", base+6, base+4)
	// Fixture teardown removes only owned rows. Disable immutable proof guards only
	// as migration owner for fixture removal, never through runtime API roles.
	t.Cleanup(func() {
		tx, err := owner.Begin(ctx)
		if err != nil {
			t.Error(err)
			return
		}
		defer tx.Rollback(ctx)
		cleanup := func(sql string, args ...any) {
			t.Helper()
			params := append([]any{pgx.QueryExecModeSimpleProtocol}, args...)
			if _, err := tx.Exec(ctx, sql, params...); err != nil {
				t.Error(err)
			}
		}
		cleanup(`ALTER TABLE cheesetrap.report_evidence DISABLE TRIGGER USER; ALTER TABLE cheesetrap.report_window_completions DISABLE TRIGGER USER;
 ALTER TABLE cheesetrap.detection_evidence DISABLE TRIGGER USER; ALTER TABLE cheesetrap.detection_evidence_chunks DISABLE TRIGGER USER;
 ALTER TABLE cheesetrap.evidence_chunk_members DISABLE TRIGGER USER; ALTER TABLE cheesetrap.evidence_chunks DISABLE TRIGGER USER`)
		if report != "" {
			cleanup("DELETE FROM cheesetrap.report_evidence WHERE report_id=$1; DELETE FROM cheesetrap.reports WHERE report_id=$1", report)
		}
		if window != "" {
			cleanup("DELETE FROM cheesetrap.report_window_completions WHERE window_id=$1; DELETE FROM cheesetrap.report_windows WHERE window_id=$1", window)
		}
		cleanup(`DELETE FROM cheesetrap.detection_evidence WHERE event_id=ANY($1::uuid[]); DELETE FROM cheesetrap.detection_evidence_chunks WHERE detection_id IN(SELECT detection_id FROM cheesetrap.detection_results WHERE source_ip='192.0.2.204'); DELETE FROM cheesetrap.evidence_chunk_members WHERE event_id=ANY($1::uuid[])`, ids[1:])
		cleanup(`DELETE FROM cheesetrap.evidence_chunks WHERE chunk_id='60000000-0000-4000-8000-000000005041'; DELETE FROM cheesetrap.detection_results WHERE source_ip='192.0.2.204'; DELETE FROM cheesetrap.detection_completions WHERE event_id=ANY($1::uuid[]); DELETE FROM cheesetrap.events WHERE sensor_id=$2`, ids[1:], sensor)
		cleanup("DELETE FROM cheesetrap.file_generations WHERE sensor_id=$1; DELETE FROM cheesetrap.sensors WHERE sensor_id=$1", sensor)
		cleanup(`ALTER TABLE cheesetrap.report_evidence ENABLE TRIGGER USER; ALTER TABLE cheesetrap.report_window_completions ENABLE TRIGGER USER;
 ALTER TABLE cheesetrap.detection_evidence ENABLE TRIGGER USER; ALTER TABLE cheesetrap.detection_evidence_chunks ENABLE TRIGGER USER;
 ALTER TABLE cheesetrap.evidence_chunk_members ENABLE TRIGGER USER; ALTER TABLE cheesetrap.evidence_chunks ENABLE TRIGGER USER`)
		cleanup("UPDATE cheesetrap.processing_cursors SET ingested_seq=$1,detected_seq=$2", ingested, detected)
		if err = tx.Commit(ctx); err != nil {
			t.Error(err)
		}
	})
	addDetection := func(process int, members []string, chunks bool) {
		t.Helper()
		tx, err := owner.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		_, err = tx.Exec(ctx, "INSERT INTO cheesetrap.detection_completions(ingestion_seq,event_id,rule_set_version) VALUES($1,$2,'1')", base+int64(process), ids[process])
		if err != nil {
			t.Fatal(err)
		}
		representation := "legacy"
		if chunks {
			representation = "chunks-v1"
		}
		var did string
		err = tx.QueryRow(ctx, `INSERT INTO cheesetrap.detection_results(rule_id,rule_version,processing_event_id,processing_ingestion_seq,source_ip,window_start,window_end,evidence_hash,evidence_count,evidence_eligible,auto_approval_allowed,explanation,evidence_representation) VALUES('SSH-REPEAT','1',$1,$2,'192.0.2.204',now(),now(),cheesetrap.evidence_set_hash($3::uuid[]),$4,true,false,'{}',$5) RETURNING detection_id`, ids[process], base+int64(process), members, len(members), representation).Scan(&did)
		if err != nil {
			t.Fatal(err)
		}
		if chunks {
			const cid = "60000000-0000-4000-8000-000000005041"
			_, err = tx.Exec(ctx, `INSERT INTO cheesetrap.evidence_chunks(chunk_id,bucket_width,bucket_no,content_hash,member_count) VALUES($1,128,$2,cheesetrap.chunk_content_hash(128,$2,$3::uuid[]),$4)`, cid, base/128, members, len(members))
			if err != nil {
				t.Fatal(err)
			}
			_, err = tx.Exec(ctx, `INSERT INTO cheesetrap.evidence_chunk_members(chunk_id,event_id) SELECT $1,unnest($2::uuid[])`, cid, members)
			if err != nil {
				t.Fatal(err)
			}
			_, err = tx.Exec(ctx, `INSERT INTO cheesetrap.detection_evidence_chunks(detection_id,bucket_no,chunk_id) VALUES($1,$2,$3)`, did, base/128, cid)
		} else {
			_, err = tx.Exec(ctx, `INSERT INTO cheesetrap.detection_evidence(detection_id,event_id) SELECT $1,unnest($2::uuid[])`, did, members)
		}
		if err != nil {
			t.Fatal(err)
		}
		if err = tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
	addDetection(4, ids[1:3], false)
	_, cookies := login(t, h)
	get := func(query string) map[string]any {
		t.Helper()
		return decodeReview(t, request(h, "GET", "/api/v1/events?event_type=result.test"+query, "", nil, cookies...), 200)
	}
	expect := func(page map[string]any, want string, seqs ...int) {
		t.Helper()
		items := page["items"].([]any)
		if len(items) != len(seqs) {
			t.Fatalf("items=%v want %v", items, seqs)
		}
		for i, v := range items {
			e := v.(map[string]any)
			if e["ingestion_seq"] != fmt.Sprint(base+int64(seqs[i])) || e["detection_result"] != want {
				t.Fatalf("event=%v want %s %d", e, want, seqs[i])
			}
		}
	}
	expect(get("&detection_result=pending"), "pending", 6, 5)
	pendingFirst := get("&detection_result=pending&limit=1")
	expect(pendingFirst, "pending", 6)
	expect(get("&detection_result=pending&source_ip=192.0.2.204&service=ssh&is_test=false&since=2001-01-01T00:00:00Z&until=2100-01-01T00:00:00Z"), "pending", 6, 5)
	for _, filter := range []string{"source_ip=192.0.2.205", "service=http", "is_test=true", "since=2100-01-01T00:00:00Z", "until=2001-01-01T00:00:00Z"} {
		expect(get("&detection_result=pending&"+filter), "pending")
	}

	first := get("&detection_result=no_match&limit=1")
	expect(first, "no_match", 4)
	expect(get("&detection_result=evidence"), "evidence", 2, 1)
	// A later processing event references an older event. Pagination retains the
	// original classification; a fresh request sees new chunk membership.
	addDetection(5, ids[2:4], true)
	// Many roots share the same exact two-member chunk. Neither the processing
	// event nor other events in its bucket become evidence. Exercise real API
	// filtering/pagination with the actual installed classifier and proof guards.
	txFanout, err := owner.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer txFanout.Rollback(ctx)
	if _, err := txFanout.Exec(ctx, `INSERT INTO cheesetrap.detection_results(rule_id,rule_version,processing_event_id,processing_ingestion_seq,source_ip,window_start,window_end,evidence_hash,evidence_count,evidence_eligible,auto_approval_allowed,explanation,evidence_representation)
 SELECT d.rule_id,'fanout-'||n,d.processing_event_id,d.processing_ingestion_seq,d.source_ip,d.window_start,d.window_end,d.evidence_hash,d.evidence_count,d.evidence_eligible,d.auto_approval_allowed,d.explanation,d.evidence_representation FROM cheesetrap.detection_results d CROSS JOIN generate_series(1,128)n WHERE d.processing_event_id=$1 AND d.rule_version='1';
 INSERT INTO cheesetrap.detection_evidence_chunks(detection_id,bucket_no,chunk_id)
 SELECT d.detection_id,c.bucket_no,c.chunk_id FROM cheesetrap.detection_results d CROSS JOIN cheesetrap.evidence_chunks c WHERE d.processing_event_id=$1 AND d.rule_version LIKE 'fanout-%' AND c.chunk_id='60000000-0000-4000-8000-000000005041'`, pgx.QueryExecModeSimpleProtocol, ids[5]); err != nil {
		t.Fatal(err)
	}
	if err := txFanout.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	exec("UPDATE cheesetrap.processing_cursors SET detected_seq=$1", base+5)
	expect(get("&detection_result=no_match&limit=1&cursor="+first["next_cursor"].(string)), "no_match", 3)
	expect(get("&detection_result=evidence"), "evidence", 3, 2, 1)
	expect(get("&detection_result=no_match"), "no_match", 5, 4)
	// Projection and filtered predicates classify the same event membership.
	mixed := get("")["items"].([]any)
	wantMixed := []string{"pending", "no_match", "no_match", "evidence", "evidence", "evidence"}
	if len(mixed) != len(wantMixed) {
		t.Fatalf("unfiltered items=%d", len(mixed))
	}
	for i, item := range mixed {
		if item.(map[string]any)["detection_result"] != wantMixed[i] {
			t.Fatalf("unfiltered classification mismatch at%d: %v", i, item)
		}
	}
	expect(get("&detection_result=pending&limit=1&cursor="+pendingFirst["next_cursor"].(string)), "pending", 5)

	expect(get("&detection_result=pending"), "pending", 6)
	// Batch report copies preserve the earliest bound across shared references.
	if err := owner.QueryRow(ctx, `INSERT INTO cheesetrap.report_windows(start_at,end_at,settings_version,state,sealed_seq,sealed_at,ready_at) VALUES(now()-interval '40 days',now()-interval '30 days',1,'ready',0,now(),now()) RETURNING window_id`).Scan(&window); err != nil {
		t.Fatal(err)
	}
	if err := owner.QueryRow(ctx, `INSERT INTO cheesetrap.reports(window_id,source_ip) VALUES($1,'192.0.2.204') RETURNING report_id`, window).Scan(&report); err != nil {
		t.Fatal(err)
	}
	if _, err := worker.Exec(ctx, `INSERT INTO cheesetrap.report_evidence(event_id,report_id,snapshot) SELECT unnest($1::uuid[]),$2,'{}'::jsonb`, ids[1:4], report); err != nil {
		t.Fatal(err)
	}
	var remembered int64
	if err := owner.QueryRow(ctx, `SELECT first_detection_seq FROM cheesetrap.event_evidence_history WHERE event_id=$1`, ids[2]).Scan(&remembered); err != nil || remembered != base+4 {
		t.Fatalf("shared membership history=%d err=%v", remembered, err)
	}
	expect(get("&detection_result=no_match&limit=1&cursor="+first["next_cursor"].(string)), "no_match", 3)

	// Old unfiltered v1 cursors remain usable, but cannot acquire a new filter.
	raw, _ := json.Marshal([]string{"", "", "result.test", "", "", ""})
	sum := sha256.Sum256(raw)
	raw, _ = json.Marshal(cursor{Version: 1, Snapshot: fmt.Sprint(base + 6), Before: fmt.Sprint(base + 3), Filters: hex.EncodeToString(sum[:])})
	legacy := base64.RawURLEncoding.EncodeToString(raw)
	expect(get("&cursor="+legacy), "evidence", 2, 1)
	if w := request(h, "GET", "/api/v1/events?event_type=result.test&detection_result=evidence&cursor="+legacy, "", nil, cookies...); w.Code != 400 {
		t.Fatalf("legacy filter cursor status=%d", w.Code)
	}
	// Loss of retained events makes a snapshot unavailable instead of silently
	// skipping rows. Refreshing produces a valid new snapshot.
	current := get("&limit=1")
	exec("DELETE FROM cheesetrap.events WHERE event_id=$1", ids[6])
	if w := request(h, "GET", "/api/v1/events?event_type=result.test&limit=1&cursor="+current["next_cursor"].(string), "", nil, cookies...); w.Code != 409 {
		t.Fatalf("stale cursor status=%d", w.Code)
	}
	get("")
	// Real bounded retention removes roots and their physical memberships while
	// retaining the newer evidence events. Their historical result must survive.
	exec("UPDATE cheesetrap.events SET ingested_at=now()-interval '35 days' WHERE event_id=ANY($1::uuid[])", ids[4:6])
	exec("INSERT INTO cheesetrap.report_window_completions(window_id) VALUES($1)", window)
	for i := 0; i < 3; i++ {
		if _, err := worker.Exec(ctx, "SELECT * FROM cheesetrap.retention_cleanup(clock_timestamp(),1000)"); err != nil {
			t.Fatal(err)
		}
	}
	var roots int
	if err := owner.QueryRow(ctx, "SELECT count(*) FROM cheesetrap.detection_results WHERE source_ip='192.0.2.204'").Scan(&roots); err != nil || roots != 0 {
		t.Fatalf("roots=%d err=%v", roots, err)
	}
	expect(get("&detection_result=evidence"), "evidence", 3, 2, 1)
	// The fixture has no rendered revision; simulate terminal copy removal as
	// migration owner after the real root cleanup, preserving runtime guards.
	tx, err := owner.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, "ALTER TABLE cheesetrap.report_evidence DISABLE TRIGGER immutable_report_evidence"); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, "DELETE FROM cheesetrap.report_evidence WHERE report_id=$1", report); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, "ALTER TABLE cheesetrap.report_evidence ENABLE TRIGGER immutable_report_evidence"); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	expect(get("&detection_result=evidence"), "evidence", 3, 2, 1)
}
