//go:build integration

package reporting

import (
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"testing"
	"time"

	"cheesetrap/internal/store"
	"cheesetrap/internal/store/db"
	"github.com/jackc/pgx/v5"
)

// Capture the generated query actually executed, so EXPLAIN cannot accidentally
// measure an independent SQL copy that has drifted from the production reader.
type sharedReadQueryCapture struct {
	pgx.Tx
	sql  string
	args []any
}

func (c *sharedReadQueryCapture) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	c.sql, c.args = sql, args
	return c.Tx.Query(ctx, sql, args...)
}

func TestSharedReportReadsVisitPhysicalMembersOnce(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	owner, err := store.NewPool(ctx, os.Getenv("CHEESETRAP_TEST_REVISION_MIGRATION_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	tx, err := owner.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := tx.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	const roots, members, chunks = 256, 1024, 8
	// All 256 roots share eight immutable chunks (262,144 logical members).
	// Distinct physical members and references together are only 3,072 rows.
	exec(`INSERT INTO cheesetrap.sensors(sensor_id,name,engine,public_ip,public_port) VALUES('10000000-0000-4000-8000-000000000405','shared-reads','cowrie','8.8.8.8',2222)`)
	exec(`INSERT INTO cheesetrap.file_generations(file_generation_id,sensor_id,path,device,inode) VALUES('20000000-0000-4000-8000-000000000405','10000000-0000-4000-8000-000000000405','/shared-reads',1,1)`)
	exec(`INSERT INTO cheesetrap.events(sensor_id,file_generation_id,byte_offset,ingestion_seq,schema_version,engine,observed_at,ingested_at,source_ip,service,event_type,raw_hash)
 SELECT '10000000-0000-4000-8000-000000000405','20000000-0000-4000-8000-000000000405',n,1024000+n,1,'cowrie','2000-01-01'::timestamptz,'2000-01-02'::timestamptz,'1.1.1.1','ssh','cowrie.login.failed',repeat('a',64) FROM generate_series(1,1024)n`)
	exec(`INSERT INTO cheesetrap.detection_completions(ingestion_seq,event_id,rule_set_version) SELECT ingestion_seq,event_id,'1' FROM cheesetrap.events WHERE file_generation_id='20000000-0000-4000-8000-000000000405'`)
	exec(`WITH evidence AS (SELECT array_agg(event_id ORDER BY event_id) ids FROM cheesetrap.events WHERE file_generation_id='20000000-0000-4000-8000-000000000405')
 INSERT INTO cheesetrap.detection_results(rule_id,rule_version,processing_event_id,processing_ingestion_seq,source_ip,window_start,window_end,evidence_hash,evidence_count,evidence_eligible,auto_approval_allowed,explanation,evidence_representation)
 SELECT 'SSH-REPEAT','1',e.event_id,e.ingestion_seq,'1.1.1.1','2000-01-01','2000-01-01',cheesetrap.evidence_set_hash(ids),1024,true,true,'{"count":1024}','chunks-v1'
 FROM cheesetrap.events e CROSS JOIN evidence WHERE e.ingestion_seq BETWEEN 1024001 AND 1024256`)
	exec(`SELECT cheesetrap.store_detection_chunks(detection_id,128,(SELECT array_agg(event_id ORDER BY event_id) FROM cheesetrap.events WHERE file_generation_id='20000000-0000-4000-8000-000000000405')) FROM cheesetrap.detection_results WHERE processing_ingestion_seq=1024001`)
	exec(`INSERT INTO cheesetrap.detection_evidence_chunks SELECT d.detection_id,r.bucket_no,r.chunk_id FROM cheesetrap.detection_results d CROSS JOIN cheesetrap.detection_evidence_chunks r JOIN cheesetrap.detection_results first ON first.detection_id=r.detection_id AND first.processing_ingestion_seq=1024001 WHERE d.processing_ingestion_seq BETWEEN 1024002 AND 1024256`)
	// Validate this as a legal complete fixture before looking at a query plan.
	exec(`SET CONSTRAINTS ALL IMMEDIATE`)
	var w db.CheesetrapReportWindow
	if err := tx.QueryRow(ctx, `INSERT INTO cheesetrap.report_windows(start_at,end_at,settings_version,state,sealed_seq,sealed_at,ready_at) VALUES('2000-01-02','2000-01-03',1,'ready',1025024,'2000-01-03','2000-01-03') RETURNING window_id,start_at,end_at`).Scan(&w.WindowID, &w.StartAt, &w.EndAt); err != nil {
		t.Fatal(err)
	}
	exec(`ANALYZE cheesetrap.events; ANALYZE cheesetrap.detection_results; ANALYZE cheesetrap.detection_evidence_chunks; ANALYZE cheesetrap.evidence_chunk_members`)
	capture := &sharedReadQueryCapture{Tx: tx}
	q := db.New(capture)
	source := netip.MustParseAddr("1.1.1.1")
	for _, kind := range []string{"source_detections", "candidate_evidence"} {
		t.Run(kind, func(t *testing.T) {
			if kind == "source_detections" {
				ds, err := q.ListReportSourceDetections(ctx, db.ListReportSourceDetectionsParams{WindowID: w.WindowID, SourceIp: source})
				if err != nil {
					t.Fatal(err)
				}
				if len(ds) != roots {
					t.Fatalf("roots=%d, want %d", len(ds), roots)
				}
				for _, d := range ds {
					if d.AttachedCount != members || d.EvidenceCount != members {
						t.Fatalf("changed root counts: %+v", d)
					}
				}
			} else {
				es, err := q.ListReportCandidateEvidence(ctx, db.ListReportCandidateEvidenceParams{WindowID: w.WindowID, SourceIp: source})
				if err != nil {
					t.Fatal(err)
				}
				if len(es) != members {
					t.Fatalf("evidence=%d, want %d", len(es), members)
				}
				for i, e := range es {
					if e.IngestionSeq != 1024001+int64(i) {
						t.Fatal("evidence order or identity changed")
					}
				}
			}
			var raw []byte
			if err := tx.QueryRow(ctx, "EXPLAIN (ANALYZE, FORMAT JSON) "+capture.sql, capture.args...).Scan(&raw); err != nil {
				t.Fatal(err)
			}
			var plan []struct{ Plan sharedReadPlanNode }
			if err := json.Unmarshal(raw, &plan); err != nil {
				t.Fatal(err)
			}
			// Check both scans and joins above membership. A single physical scan can
			// still explode at a root/member join before a late DISTINCT collapses it.
			scans, expanded := plan[0].Plan.memberWork()
			budget := float64(4 * (members + roots*chunks))
			t.Logf("physical members=%d references=%d member scan rows*loops=%.0f largest member subtree rows*loops=%.0f budget=%.0f", members, roots*chunks, scans, expanded, budget)
			if scans > budget || expanded > budget {
				t.Errorf("shared membership expanded per root: scan=%.0f expanded=%.0f, budget=%.0f", scans, expanded, budget)
			}
		})
	}
	// Assignment to another source is global and reduces every shared root's
	// attached count without changing its original context count or hash.
	exec(`WITH report AS (INSERT INTO cheesetrap.reports(window_id,source_ip) VALUES($1,'9.9.9.9') RETURNING report_id)
 INSERT INTO cheesetrap.report_evidence SELECT e.event_id,r.report_id,'{}' FROM cheesetrap.events e CROSS JOIN report r
 WHERE e.file_generation_id='20000000-0000-4000-8000-000000000405' AND e.ingestion_seq%2=0`, w.WindowID)
	for _, owned := range []int{members / 2, members} {
		if owned == members {
			exec(`INSERT INTO cheesetrap.report_evidence SELECT e.event_id,r.report_id,'{}' FROM cheesetrap.events e
   JOIN cheesetrap.reports r ON r.window_id=$1 AND r.source_ip='9.9.9.9'
   WHERE e.file_generation_id='20000000-0000-4000-8000-000000000405' AND e.ingestion_seq%2=1`, w.WindowID)
		}
		ds, err := q.ListReportSourceDetections(ctx, db.ListReportSourceDetectionsParams{WindowID: w.WindowID, SourceIp: source})
		if err != nil {
			t.Fatal(err)
		}
		if len(ds) != roots {
			t.Fatalf("ownership hid roots: got %d want %d", len(ds), roots)
		}
		for _, d := range ds {
			if d.AttachedCount != int64(members-owned) || d.EvidenceCount != members {
				t.Fatalf("ownership changed counts: %+v", d)
			}
		}
		es, err := q.ListReportCandidateEvidence(ctx, db.ListReportCandidateEvidenceParams{WindowID: w.WindowID, SourceIp: source})
		if err != nil {
			t.Fatal(err)
		}
		if len(es) != members-owned {
			t.Fatalf("owned=%d evidence=%d", owned, len(es))
		}
		for i, e := range es {
			if e.IngestionSeq != 1024001+2*int64(i) {
				t.Fatal("owned evidence leaked or ordering changed")
			}
		}
	}
}

type sharedReadPlanNode struct {
	Relation string               `json:"Relation Name"`
	Rows     float64              `json:"Actual Rows"`
	Loops    float64              `json:"Actual Loops"`
	Plans    []sharedReadPlanNode `json:"Plans"`
}

func (n sharedReadPlanNode) memberWork() (scans, expanded float64) {
	if n.Relation == "evidence_chunk_members" {
		scans = n.Rows * n.Loops
		expanded = scans
	}
	for _, child := range n.Plans {
		s, e := child.memberWork()
		scans += s
		if e > expanded {
			expanded = e
		}
	}
	if scans > 0 && n.Rows*n.Loops > expanded {
		expanded = n.Rows * n.Loops
	}
	return scans, expanded
}

// Distinct singleton evidence makes every excluded root visible as a leaked
// candidate, covering both readers' trigger, sequence, state and source filters.
func TestSharedReportReadsTriggerBoundaries(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	owner, err := store.NewPool(ctx, os.Getenv("CHEESETRAP_TEST_REVISION_MIGRATION_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	tx, err := owner.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := tx.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO cheesetrap.sensors(sensor_id,name,engine,public_ip,public_port) VALUES('10000000-0000-4000-8000-000000000406','shared-boundaries','cowrie','8.8.8.8',2222)`)
	exec(`INSERT INTO cheesetrap.file_generations(file_generation_id,sensor_id,path,device,inode) VALUES('20000000-0000-4000-8000-000000000406','10000000-0000-4000-8000-000000000406','/shared-boundaries',1,1)`)
	exec(`INSERT INTO cheesetrap.events(sensor_id,file_generation_id,byte_offset,ingestion_seq,schema_version,engine,observed_at,ingested_at,source_ip,service,event_type,raw_hash)
 SELECT '10000000-0000-4000-8000-000000000406','20000000-0000-4000-8000-000000000406',n,2048000+n,1,'cowrie','1999-01-01'::timestamptz,
 CASE n WHEN 1 THEN '2001-01-01 23:59:59.999999+00'::timestamptz WHEN 3 THEN '2001-01-02 23:59:59.999999+00'::timestamptz WHEN 4 THEN '2001-01-03'::timestamptz ELSE '2001-01-02'::timestamptz END,
 '1.1.1.1','ssh','cowrie.login.failed',repeat('a',64) FROM generate_series(1,8)n`)
	exec(`INSERT INTO cheesetrap.detection_completions(ingestion_seq,event_id,rule_set_version) SELECT ingestion_seq,event_id,'1' FROM cheesetrap.events WHERE file_generation_id='20000000-0000-4000-8000-000000000406'`)
	exec(`INSERT INTO cheesetrap.detection_results(rule_id,rule_version,processing_event_id,processing_ingestion_seq,source_ip,window_start,window_end,evidence_hash,evidence_count,evidence_eligible,auto_approval_allowed,explanation,evidence_representation)
 SELECT 'SSH-REPEAT','1',event_id,ingestion_seq,CASE WHEN byte_offset=5 THEN '9.9.9.9'::inet ELSE source_ip END,'1999-01-01','1999-01-01',cheesetrap.evidence_set_hash(ARRAY[event_id]),1,true,true,'{"count":1}',CASE WHEN byte_offset%2=0 THEN 'legacy' ELSE 'chunks-v1' END
 FROM cheesetrap.events WHERE file_generation_id='20000000-0000-4000-8000-000000000406'`)
	exec(`INSERT INTO cheesetrap.detection_evidence SELECT detection_id,processing_event_id FROM cheesetrap.detection_results WHERE processing_ingestion_seq BETWEEN 2048001 AND 2048008 AND evidence_representation='legacy'`)
	exec(`SELECT cheesetrap.store_detection_chunks(detection_id,128,ARRAY[processing_event_id]) FROM cheesetrap.detection_results WHERE processing_ingestion_seq BETWEEN 2048001 AND 2048008 AND evidence_representation='chunks-v1'`)
	exec(`SET CONSTRAINTS ALL IMMEDIATE`)
	exec(`ALTER TABLE cheesetrap.detection_results DISABLE TRIGGER guard_evidence_root`)
	exec(`UPDATE cheesetrap.detection_results SET evidence_state='retiring' WHERE processing_ingestion_seq=2048006`)
	var w db.CheesetrapReportWindow
	if err := tx.QueryRow(ctx, `INSERT INTO cheesetrap.report_windows(start_at,end_at,settings_version,state,sealed_seq,sealed_at,ready_at) VALUES('2001-01-02','2001-01-03',1,'ready',2048007,'2001-01-03','2001-01-03') RETURNING window_id,start_at,end_at`).Scan(&w.WindowID, &w.StartAt, &w.EndAt); err != nil {
		t.Fatal(err)
	}
	q := db.New(tx)
	snapshot, err := collectEvidence(ctx, q, w, "1.1.1.1")
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Rules) != 3 || len(snapshot.Evidence) != 3 || !snapshot.DelayedCollection {
		t.Fatalf("trigger boundary snapshot: %+v", snapshot)
	}
	expected := []int64{2048002, 2048003, 2048007}
	ds, err := q.ListReportSourceDetections(ctx, db.ListReportSourceDetectionsParams{WindowID: w.WindowID, SourceIp: netip.MustParseAddr("1.1.1.1")})
	if err != nil {
		t.Fatal(err)
	}
	for i, seq := range expected {
		if snapshot.Evidence[i].IngestionSeq != seq || ds[i].ProcessingIngestionSeq != seq || snapshot.Rules[i].AttachedCount != 1 || snapshot.Rules[i].ContextCount != 1 {
			t.Fatal("trigger boundary membership/order/count changed")
		}
	}
	// An entirely owned legacy/chunk mixture still returns its roots with zero
	// attached members, and no evidence from excluded or retiring singleton roots.
	exec(`WITH r AS (INSERT INTO cheesetrap.reports(window_id,source_ip) VALUES($1,'8.8.8.8') RETURNING report_id)
 INSERT INTO cheesetrap.report_evidence SELECT e.event_id,r.report_id,'{}' FROM cheesetrap.events e CROSS JOIN r WHERE e.ingestion_seq=ANY($2::bigint[])`, w.WindowID, expected)
	snapshot, err = collectEvidence(ctx, q, w, "1.1.1.1")
	if err != nil || len(snapshot.Evidence) != 0 || len(snapshot.Rules) != 3 {
		t.Fatalf("owned mixed snapshot: %+v error=%v", snapshot, err)
	}
	for _, r := range snapshot.Rules {
		if r.AttachedCount != 0 || r.ContextCount != 1 {
			t.Fatal("zero attached changed context")
		}
	}
	// A sealed window cannot expose these otherwise eligible triggers.
	if err := tx.QueryRow(ctx, `INSERT INTO cheesetrap.report_windows(start_at,end_at,settings_version,state,sealed_seq,sealed_at) VALUES('2001-01-01','2001-01-04',1,'sealed',2048008,'2001-01-04') RETURNING window_id`).Scan(&w.WindowID); err != nil {
		t.Fatal(err)
	}
	snapshot, err = collectEvidence(ctx, q, w, "1.1.1.1")
	if err != nil || len(snapshot.Rules) != 0 || len(snapshot.Evidence) != 0 {
		t.Fatal("non-ready window exposed evidence", err)
	}
}
