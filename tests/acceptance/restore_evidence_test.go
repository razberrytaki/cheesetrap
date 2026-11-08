//go:build integration

package acceptance

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"cheesetrap/internal/retention"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Keep the physical representation as well as resolved membership in the oracle:
// restoring only equivalent event IDs must not silently lose sharing or metadata.
const restoreEvidenceSnapshot = `SELECT jsonb_build_object(
 'roots',(SELECT jsonb_agg(to_jsonb(d) ORDER BY detection_id) FROM cheesetrap.detection_results d),
 'legacy',(SELECT jsonb_agg(to_jsonb(d) ORDER BY detection_id,event_id) FROM cheesetrap.detection_evidence d),
 'chunks',(SELECT jsonb_agg(to_jsonb(c) ORDER BY chunk_id) FROM cheesetrap.evidence_chunks c),
 'members',(SELECT jsonb_agg(to_jsonb(m) ORDER BY chunk_id,event_id) FROM cheesetrap.evidence_chunk_members m),
 'refs',(SELECT jsonb_agg(to_jsonb(r) ORDER BY detection_id,bucket_no) FROM cheesetrap.detection_evidence_chunks r),
 'resolved',(SELECT jsonb_agg(to_jsonb(m) ORDER BY detection_id,event_id) FROM cheesetrap.detection_evidence_membership m),
 'revisions',(SELECT jsonb_agg(to_jsonb(r) ORDER BY revision_id) FROM cheesetrap.report_revisions r),
 'copies',(SELECT jsonb_agg(to_jsonb(e) ORDER BY event_id) FROM cheesetrap.report_evidence e),
 'events',(SELECT jsonb_agg(to_jsonb(e) ORDER BY ingestion_seq) FROM cheesetrap.events e),
 'cursor',(SELECT to_jsonb(c) FROM cheesetrap.processing_cursors c WHERE singleton)
)::text`

func seedRestoreEvidence(t *testing.T, ctx context.Context, owner, worker *pgxpool.Pool, reportID string) string {
	t.Helper()
	_, err := owner.Exec(ctx, `INSERT INTO cheesetrap.sensors(sensor_id,name,engine) VALUES('10000000-0000-0000-0000-000000000017','restore-chunks','cowrie');
 INSERT INTO cheesetrap.file_generations(file_generation_id,sensor_id,path,device,inode) VALUES('20000000-0000-0000-0000-000000000017','10000000-0000-0000-0000-000000000017','/restore-chunks',17,17);
 INSERT INTO cheesetrap.events(event_id,sensor_id,file_generation_id,byte_offset,ingestion_seq,schema_version,engine,source_ip,destination_ip,destination_port,service,event_type,attributes,raw_hash)
 SELECT ('00000000-0000-0000-0000-'||lpad(n::text,12,'0'))::uuid,'10000000-0000-0000-0000-000000000017','20000000-0000-0000-0000-000000000017',n,n,1,'cowrie','1.1.1.1','8.8.8.8',22,'ssh','login.failed','{}',repeat('a',64) FROM generate_series(1,130)n;
 UPDATE cheesetrap.processing_cursors SET ingested_seq=130,detected_seq=130;
 INSERT INTO cheesetrap.detection_completions(ingestion_seq,event_id,rule_set_version) SELECT ingestion_seq,event_id,'1' FROM cheesetrap.events;`)
	if err != nil {
		t.Fatal(err)
	}
	ids := `ARRAY['00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000002','00000000-0000-0000-0000-000000000130']::uuid[]`
	sum := sha256.Sum256([]byte(`["00000000-0000-0000-0000-000000000001","00000000-0000-0000-0000-000000000002","00000000-0000-0000-0000-000000000130"]`))
	hash := hex.EncodeToString(sum[:])
	for i, format := range []string{"legacy", "chunks-v1", "chunks-v1"} {
		tx, err := worker.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		id := fmt.Sprintf("30000000-0000-0000-0000-%012d", i+1)
		_, err = tx.Exec(ctx, `INSERT INTO cheesetrap.detection_results(detection_id,rule_id,rule_version,processing_event_id,processing_ingestion_seq,source_ip,window_start,window_end,evidence_hash,evidence_count,evidence_eligible,auto_approval_allowed,explanation,evidence_representation) VALUES($1,'SSH-REPEAT',$3,'00000000-0000-0000-0000-000000000130',130,'1.1.1.1',now(),now(),$4,3,false,true,'{"fixture":"restore"}',$2)`, id, format, id, hash)
		if err == nil {
			if format == "legacy" {
				_, err = tx.Exec(ctx, `INSERT INTO cheesetrap.detection_evidence SELECT $1,unnest(`+ids+`)`, id)
			} else {
				_, err = tx.Exec(ctx, `SELECT cheesetrap.store_detection_chunks($1,128,`+ids+`)`, id)
			}
		}
		if err != nil {
			tx.Rollback(ctx)
			t.Fatal(err)
		}
		if err = tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
	_, err = owner.Exec(ctx, `INSERT INTO cheesetrap.report_evidence(event_id,report_id,snapshot) SELECT event_id,$1,jsonb_build_object('event_id',event_id,'raw_hash',raw_hash) FROM cheesetrap.events WHERE event_id=ANY(`+ids+`)`, reportID)
	if err != nil {
		t.Fatal(err)
	}
	var count int
	if err = owner.QueryRow(ctx, `SELECT count(*) FROM cheesetrap.evidence_chunks`).Scan(&count); err != nil || count != 2 {
		t.Fatalf("shared chunk fixture: count=%d err=%v", count, err)
	}
	var before string
	if err = owner.QueryRow(ctx, restoreEvidenceSnapshot).Scan(&before); err != nil {
		t.Fatal(err)
	}
	return before
}

func verifyRestoredEvidence(t *testing.T, ctx context.Context, owner, worker *pgxpool.Pool, before string) {
	t.Helper()
	var after string
	if err := owner.QueryRow(ctx, restoreEvidenceSnapshot).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Fatal("backup/restore changed exact mixed evidence, shared chunks, copies or cursor")
	}
	// Replay both representations through the restored worker grant; no rewrite.
	for i := 1; i <= 3; i++ {
		_, err := worker.Exec(ctx, `SELECT cheesetrap.store_detection_chunks($1,128,ARRAY['00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000002','00000000-0000-0000-0000-000000000130']::uuid[])`, fmt.Sprintf("30000000-0000-0000-0000-%012d", i))
		if err != nil {
			t.Fatal(err)
		}
	}
	// Fresh uncopied/unexpired roots must survive normal restored cleanup.
	if _, err := retention.Cleanup(ctx, worker, time.Now().UTC(), 1); err != nil {
		t.Fatal(err)
	}
	if err := owner.QueryRow(ctx, restoreEvidenceSnapshot).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Fatal("restored replay/cleanup changed protected mixed evidence")
	}
	if _, err := worker.Exec(ctx, `DELETE FROM cheesetrap.evidence_chunk_members`); err == nil {
		t.Fatal("restore broadened worker evidence permissions")
	}
}
