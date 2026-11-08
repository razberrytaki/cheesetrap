//go:build integration

package retention

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

// Valid exact shared sets are written through the production attachment function.
// Each test rolls back the entire fixture, including deliberate damage checks.
func sharedProofFixture(t *testing.T) (context.Context, pgx.Tx) {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, os.Getenv("CHEESETRAP_TEST_RETENTION_MIGRATION_URL"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close(ctx) })
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tx.Rollback(ctx) })
	proofExec(t, ctx, tx, `INSERT INTO cheesetrap.sensors(sensor_id,name,engine) VALUES('10000000-0000-4000-8000-000000009920','shared-proof','cowrie');
 INSERT INTO cheesetrap.file_generations(file_generation_id,sensor_id,path,device,inode) VALUES('20000000-0000-4000-8000-000000009920','10000000-0000-4000-8000-000000009920','/shared-proof',1,1);
 INSERT INTO cheesetrap.events(event_id,sensor_id,file_generation_id,byte_offset,ingestion_seq,schema_version,engine,ingested_at,service,event_type,raw_hash)
 SELECT ('00000000-0000-4000-8000-'||lpad(n::text,12,'0'))::uuid,'10000000-0000-4000-8000-000000009920','20000000-0000-4000-8000-000000009920',n,n,1,'cowrie',now()-interval '40 days','ssh','test',repeat('a',64) FROM generate_series(920001,920256)n;
 INSERT INTO cheesetrap.detection_completions(event_id,ingestion_seq,rule_set_version) SELECT event_id,ingestion_seq,'1' FROM cheesetrap.events WHERE ingestion_seq BETWEEN 920001 AND 920256;
 INSERT INTO cheesetrap.report_windows(window_id,start_at,end_at,settings_version,state,sealed_seq,sealed_at,ready_at) VALUES('30000000-0000-4000-8000-000000009920',now()-interval '41 days',now()-interval '39 days',1,'ready',920256,now(),now());
 INSERT INTO cheesetrap.report_window_completions(window_id) VALUES('30000000-0000-4000-8000-000000009920');
 INSERT INTO cheesetrap.reports(report_id,window_id,source_ip,version,current_revision_id,state) VALUES('40000000-0000-4000-8000-000000009920','30000000-0000-4000-8000-000000009920','8.8.4.4',1,'50000000-0000-4000-8000-000000009920','held');
 INSERT INTO cheesetrap.report_revisions(revision_id,report_id,version,snapshot,subject,body,recipient,reply_to,hold_reasons,state,auto_approval_allowed,body_edited,content_digest) VALUES('50000000-0000-4000-8000-000000009920','40000000-0000-4000-8000-000000009920',1,'{}','s','b','a@example.org','b@example.org','{}','needs_review',false,false,repeat('a',64));
 INSERT INTO cheesetrap.report_evidence(event_id,report_id,snapshot) SELECT event_id,'40000000-0000-4000-8000-000000009920',jsonb_build_object('event_id',event_id,'hash',raw_hash) FROM cheesetrap.events WHERE ingestion_seq BETWEEN 920001 AND 920256;
 INSERT INTO cheesetrap.detection_results(detection_id,rule_id,rule_version,processing_event_id,processing_ingestion_seq,source_ip,window_start,window_end,evidence_hash,evidence_count,evidence_eligible,auto_approval_allowed,explanation,evidence_representation)
 SELECT ('60000000-0000-4000-8000-'||lpad(n::text,12,'0'))::uuid,'SSH-REPEAT','shared-proof-'||n,event_id,ingestion_seq,'8.8.4.4',ingested_at,ingested_at,(SELECT cheesetrap.evidence_set_hash(array_agg(event_id ORDER BY event_id)) FROM cheesetrap.events WHERE ingestion_seq BETWEEN 920001 AND 920256),256,false,false,'{}','chunks-v1' FROM cheesetrap.events CROSS JOIN generate_series(1,64)n WHERE ingestion_seq=920256;
 SELECT cheesetrap.store_detection_chunks(detection_id,64,(SELECT array_agg(event_id ORDER BY event_id) FROM cheesetrap.events WHERE ingestion_seq BETWEEN 920001 AND 920256)) FROM cheesetrap.detection_results WHERE rule_version LIKE 'shared-proof-%';
 SET CONSTRAINTS ALL IMMEDIATE;
 SET CONSTRAINTS ALL DEFERRED;
 ANALYZE cheesetrap.events; ANALYZE cheesetrap.detection_results; ANALYZE cheesetrap.evidence_chunks; ANALYZE cheesetrap.evidence_chunk_members; ANALYZE cheesetrap.detection_evidence_chunks; ANALYZE cheesetrap.report_evidence;`)
	return ctx, tx
}

func proofExec(t *testing.T, ctx context.Context, tx pgx.Tx, query string) {
	t.Helper()
	if _, err := tx.Exec(ctx, query); err != nil {
		t.Fatal(err)
	}
}

// Extract the actual installed active proof statement; schema20 wraps it in an
// IF branch, while schema19 has one combined selection. Both are executable SQL.
func activeProofSQL(t *testing.T, ctx context.Context, tx pgx.Tx) string {
	t.Helper()
	var definition string
	if err := tx.QueryRow(ctx, `SELECT pg_get_functiondef('cheesetrap.retention_cleanup(timestamptz,integer)'::regprocedure)`).Scan(&definition); err != nil {
		t.Fatal(err)
	}
	end := strings.Index(definition, "UPDATE cheesetrap.detection_results SET evidence_state='retiring'")
	if end < 0 {
		t.Fatal("active proof update not found")
	}
	start := strings.LastIndex(definition[:end], "SELECT array_agg(detection_id) INTO d_ids FROM (")
	if end < 0 || start < 0 {
		t.Fatal("active proof selection not found")
	}
	query := definition[start:end]
	query = query[:strings.Index(query, ";")+1]
	query = strings.Replace(query, " INTO d_ids", "", 1)
	query = strings.ReplaceAll(query, "at_time", "now()")
	query = strings.ReplaceAll(query, "event_age", "make_interval(days=>(cheesetrap.retention_policy()->>'event_days')::integer)")
	return strings.ReplaceAll(query, "batch_limit", "1000")
}

func TestRetentionSharedProofVisitsPhysicalMembersOnce(t *testing.T) {
	ctx, tx := sharedProofFixture(t)
	var raw []byte
	if err := tx.QueryRow(ctx, "EXPLAIN (ANALYZE,FORMAT JSON) "+activeProofSQL(t, ctx, tx)).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var plans []map[string]any
	if err := json.Unmarshal(raw, &plans); err != nil {
		t.Fatal(err)
	}
	visits := float64(0)
	var walk func(map[string]any)
	walk = func(node map[string]any) {
		if node["Relation Name"] == "evidence_chunk_members" {
			visits += node["Actual Rows"].(float64) * node["Actual Loops"].(float64)
		}
		children, _ := node["Plans"].([]any)
		for _, child := range children {
			walk(child.(map[string]any))
		}
	}
	walk(plans[0]["Plan"].(map[string]any))
	t.Logf("member scan visits=%.0f physical=256 logical=16384", visits)
	if visits < 256 || visits > 512 {
		t.Fatalf("shared proof repeats physical membership: %.0f visits for 256 members", visits)
	}
	var ids []string
	if err := tx.QueryRow(ctx, activeProofSQL(t, ctx, tx)).Scan(&ids); err != nil {
		t.Fatal(err)
	}
	if len(ids) != 64 {
		t.Fatalf("eligible roots=%d want64", len(ids))
	}
}

func TestRetentionRetiringBatchDoesNotAdmitActiveRoots(t *testing.T) {
	ctx, seed := sharedProofFixture(t)
	if err := seed.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		owner, err := pgx.Connect(ctx, os.Getenv("CHEESETRAP_TEST_RETENTION_MIGRATION_URL"))
		if err != nil {
			t.Error(err)
			return
		}
		defer owner.Close(ctx)
		cleanup, err := owner.Begin(ctx)
		if err != nil {
			t.Error(err)
			return
		}
		defer cleanup.Rollback(ctx)
		for _, table := range []string{"detection_evidence_chunks", "evidence_chunk_members", "evidence_chunks", "reports", "report_revisions", "report_evidence", "report_window_completions"} {
			if _, err = cleanup.Exec(ctx, "ALTER TABLE cheesetrap."+table+" DISABLE TRIGGER USER"); err != nil {
				t.Error(err)
				return
			}
		}
		_, err = cleanup.Exec(ctx, `DELETE FROM cheesetrap.detection_evidence_chunks WHERE detection_id IN (SELECT detection_id FROM cheesetrap.detection_results WHERE rule_version LIKE 'shared-proof-%');
 DELETE FROM cheesetrap.detection_results WHERE rule_version LIKE 'shared-proof-%';
 DELETE FROM cheesetrap.evidence_chunk_members WHERE event_id IN (SELECT event_id FROM cheesetrap.events WHERE ingestion_seq BETWEEN 920001 AND 920256);
 DELETE FROM cheesetrap.evidence_chunks c WHERE bucket_width=64 AND bucket_no BETWEEN (920001-1)/64 AND (920256-1)/64 AND NOT EXISTS (SELECT 1 FROM cheesetrap.evidence_chunk_members m WHERE m.chunk_id=c.chunk_id) AND NOT EXISTS (SELECT 1 FROM cheesetrap.detection_evidence_chunks r WHERE r.chunk_id=c.chunk_id);
 DELETE FROM cheesetrap.report_evidence WHERE report_id='40000000-0000-4000-8000-000000009920';
 DELETE FROM cheesetrap.report_revisions WHERE report_id='40000000-0000-4000-8000-000000009920';
 DELETE FROM cheesetrap.reports WHERE report_id='40000000-0000-4000-8000-000000009920';
 DELETE FROM cheesetrap.report_window_completions WHERE window_id='30000000-0000-4000-8000-000000009920';
 DELETE FROM cheesetrap.report_windows WHERE window_id='30000000-0000-4000-8000-000000009920';
 DELETE FROM cheesetrap.detection_completions WHERE ingestion_seq BETWEEN 920001 AND 920256;
 DELETE FROM cheesetrap.events WHERE ingestion_seq BETWEEN 920001 AND 920256;
 DELETE FROM cheesetrap.file_generations WHERE file_generation_id='20000000-0000-4000-8000-000000009920';
 DELETE FROM cheesetrap.sensors WHERE sensor_id='10000000-0000-4000-8000-000000009920'; SET CONSTRAINTS ALL IMMEDIATE;`)
		if err != nil {
			t.Error(err)
			return
		}
		for _, table := range []string{"detection_evidence_chunks", "evidence_chunk_members", "evidence_chunks", "reports", "report_revisions", "report_evidence", "report_window_completions"} {
			if _, err = cleanup.Exec(ctx, "ALTER TABLE cheesetrap."+table+" ENABLE TRIGGER USER"); err != nil {
				t.Error(err)
				return
			}
		}
		if err = cleanup.Commit(ctx); err != nil {
			t.Error(err)
		}
	})
	worker, err := pgx.Connect(ctx, os.Getenv("CHEESETRAP_TEST_RETENTION_WORKER_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer worker.Close(ctx)
	tx, err := worker.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	// Obtain a real saved retirement decision with one bounded cleanup pass.
	proofExec(t, ctx, tx, `SELECT * FROM cheesetrap.retention_cleanup(now(),1)`)
	var before, after int
	query := `SELECT count(*) FROM cheesetrap.detection_results WHERE rule_version LIKE 'shared-proof-%' AND evidence_state='active'`
	if err := tx.QueryRow(ctx, query).Scan(&before); err != nil {
		t.Fatal(err)
	}
	proofExec(t, ctx, tx, `SELECT * FROM cheesetrap.retention_cleanup(now(),2)`)
	if err := tx.QueryRow(ctx, query).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if before != 63 || after != before {
		t.Fatalf("retiring drain admitted active proof: active before=%d after=%d", before, after)
	}
}

func TestRetentionSharedProofProtectsMissingCopiesAndMembers(t *testing.T) {
	for _, damage := range []string{"copy", "member", "reference"} {
		t.Run(damage, func(t *testing.T) {
			ctx, tx := sharedProofFixture(t)
			// Owner-only corruption represents an incomplete imported set. Header and
			// immutable root counts remain unchanged and must not substitute for proof.
			switch damage {
			case "copy":
				proofExec(t, ctx, tx, `ALTER TABLE cheesetrap.report_evidence DISABLE TRIGGER USER; DELETE FROM cheesetrap.report_evidence WHERE event_id='00000000-0000-4000-8000-000000920001'; ALTER TABLE cheesetrap.report_evidence ENABLE TRIGGER USER`)
			case "member":
				proofExec(t, ctx, tx, `ALTER TABLE cheesetrap.evidence_chunk_members DISABLE TRIGGER USER; DELETE FROM cheesetrap.evidence_chunk_members WHERE event_id='00000000-0000-4000-8000-000000920001'; ALTER TABLE cheesetrap.evidence_chunk_members ENABLE TRIGGER USER`)
			case "reference":
				proofExec(t, ctx, tx, `ALTER TABLE cheesetrap.detection_evidence_chunks DISABLE TRIGGER USER; DELETE FROM cheesetrap.detection_evidence_chunks WHERE chunk_id IN (SELECT chunk_id FROM cheesetrap.evidence_chunk_members WHERE event_id='00000000-0000-4000-8000-000000920001'); ALTER TABLE cheesetrap.detection_evidence_chunks ENABLE TRIGGER USER`)
			}
			var selected []string
			if err := tx.QueryRow(ctx, activeProofSQL(t, ctx, tx)).Scan(&selected); err != nil {
				t.Fatal(err)
			}
			if len(selected) != 0 {
				t.Fatalf("incomplete proof selected %d roots", len(selected))
			}
			var active int
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM cheesetrap.detection_results WHERE rule_version LIKE 'shared-proof-%' AND evidence_state='active'`).Scan(&active); err != nil {
				t.Fatal(err)
			}
			if active != 64 {
				t.Fatalf("%s damage lost protected roots: %d", damage, active)
			}
		})
	}
}

func TestRetentionProtectedEarlyDoesNotStarveEligibleLate(t *testing.T) {
	ctx, tx := sharedProofFixture(t)
	proofExec(t, ctx, tx, `INSERT INTO cheesetrap.events(event_id,sensor_id,file_generation_id,byte_offset,ingestion_seq,schema_version,engine,ingested_at,service,event_type,raw_hash)
 VALUES('00000000-0000-4000-8000-000000920257','10000000-0000-4000-8000-000000009920','20000000-0000-4000-8000-000000009920',920257,920257,1,'cowrie',now()-interval '40 days','ssh','test',repeat('a',64));
 INSERT INTO cheesetrap.detection_results(detection_id,rule_id,rule_version,processing_event_id,processing_ingestion_seq,source_ip,window_start,window_end,evidence_hash,evidence_count,evidence_eligible,auto_approval_allowed,explanation)
 SELECT '60000000-0000-4000-8000-000000000000','SSH-REPEAT','protected-early',event_id,ingestion_seq,'8.8.4.4',ingested_at,ingested_at,cheesetrap.evidence_set_hash(ARRAY['00000000-0000-4000-8000-000000920257']::uuid[]),1,false,false,'{}' FROM cheesetrap.events WHERE ingestion_seq=920256;
 INSERT INTO cheesetrap.detection_evidence VALUES('60000000-0000-4000-8000-000000000000','00000000-0000-4000-8000-000000920257');
 SET CONSTRAINTS ALL IMMEDIATE;`)
	var ids []string
	query := strings.Replace(activeProofSQL(t, ctx, tx), "LIMIT 1000", "LIMIT 1", 1)
	if err := tx.QueryRow(ctx, query).Scan(&ids); err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 || ids[0] != "60000000-0000-4000-8000-000000000001" {
		t.Fatalf("protected first candidate starved eligible late roots: %v", ids)
	}
}
