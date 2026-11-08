//go:build integration

package retention

import (
	"context"
	"os"
	"testing"
	"time"

	"cheesetrap/internal/store"
)

// Run both representations over the same committed input, rolling each cleanup
// transaction back so UUIDs, snapshots and timestamps are identical oracles.
// Commit the final chunk run to remove fixture events before other DB tests.
func TestChunkRetentionLegacyEquivalence(t *testing.T) {
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
	now := time.Now().UTC()
	old := now.Add(-40 * 24 * time.Hour)
	tx, err := owner.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	_, err = tx.Exec(ctx, `INSERT INTO cheesetrap.sensors(sensor_id,name,engine) VALUES('10000000-0000-4000-8000-000000000901','equivalence','cowrie');
 INSERT INTO cheesetrap.file_generations(file_generation_id,sensor_id,path,device,inode) VALUES('20000000-0000-4000-8000-000000000901','10000000-0000-4000-8000-000000000901','/equivalence',1,1);`)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec(ctx, `INSERT INTO cheesetrap.events(sensor_id,file_generation_id,byte_offset,ingestion_seq,schema_version,engine,ingested_at,service,event_type,raw_hash) SELECT '10000000-0000-4000-8000-000000000901','20000000-0000-4000-8000-000000000901',n,n,1,'cowrie',$1,'ssh','test',repeat('a',64) FROM generate_series(2001,2005)n;
 `, old)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec(ctx, `UPDATE cheesetrap.processing_cursors SET ingested_seq=2005,detected_seq=2005,sealed_before=$1`, now)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec(ctx, `INSERT INTO cheesetrap.report_windows(window_id,start_at,end_at,settings_version,state,sealed_seq,sealed_at,ready_at) VALUES('30000000-0000-4000-8000-000000000901',$1,$2,1,'ready',2005,$2,$2)`, old.Add(-time.Hour), old.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec(ctx, `INSERT INTO cheesetrap.detection_completions(event_id,ingestion_seq,rule_set_version) SELECT event_id,ingestion_seq,'1' FROM cheesetrap.events WHERE ingestion_seq BETWEEN 2001 AND 2005;
 INSERT INTO cheesetrap.report_window_completions(window_id) VALUES('30000000-0000-4000-8000-000000000901');
 INSERT INTO cheesetrap.reports(report_id,window_id,source_ip,version,current_revision_id,state) VALUES('40000000-0000-4000-8000-000000000901','30000000-0000-4000-8000-000000000901','8.8.4.4',1,'50000000-0000-4000-8000-000000000901','held');
 INSERT INTO cheesetrap.report_revisions(revision_id,report_id,version,snapshot,subject,body,recipient,reply_to,hold_reasons,state,auto_approval_allowed,body_edited,content_digest) VALUES('50000000-0000-4000-8000-000000000901','40000000-0000-4000-8000-000000000901',1,'{}','s','b','a@example.org','b@example.org','{}','needs_review',false,false,repeat('a',64));
 INSERT INTO cheesetrap.report_evidence(event_id,report_id,snapshot) SELECT event_id,'40000000-0000-4000-8000-000000000901',jsonb_build_object('event_id',event_id,'hash',raw_hash) FROM cheesetrap.events WHERE ingestion_seq BETWEEN 2001 AND 2005;`)
	if err != nil {
		t.Fatal(err)
	}
	var hash string
	if err = tx.QueryRow(ctx, `SELECT cheesetrap.evidence_set_hash(array_agg(event_id ORDER BY event_id)) FROM cheesetrap.events WHERE ingestion_seq BETWEEN 2001 AND 2005`).Scan(&hash); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	var oracle string
	for _, format := range []string{"legacy", "chunks-v1"} {
		t.Run(format, func(t *testing.T) {
			tx, err := worker.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(ctx)
			_, err = tx.Exec(ctx, `INSERT INTO cheesetrap.detection_results(detection_id,rule_id,rule_version,processing_event_id,processing_ingestion_seq,source_ip,window_start,window_end,evidence_hash,evidence_count,evidence_eligible,auto_approval_allowed,explanation,evidence_representation) SELECT '60000000-0000-4000-8000-000000000901','SSH-REPEAT','1',event_id,ingestion_seq,'8.8.4.4',ingested_at,ingested_at,$1,5,false,false,'{}',$2 FROM cheesetrap.events WHERE ingestion_seq=2005`, hash, format)
			if err != nil {
				t.Fatal(err)
			}
			if format == "legacy" {
				_, err = tx.Exec(ctx, `INSERT INTO cheesetrap.detection_evidence SELECT '60000000-0000-4000-8000-000000000901',event_id FROM cheesetrap.events WHERE ingestion_seq BETWEEN 2001 AND 2005`)
			} else {
				_, err = tx.Exec(ctx, `SELECT cheesetrap.store_detection_chunks('60000000-0000-4000-8000-000000000901',64,(SELECT array_agg(event_id ORDER BY event_id) FROM cheesetrap.events WHERE ingestion_seq BETWEEN 2001 AND 2005))`)
			}
			if err != nil {
				t.Fatal(err)
			}
			// Prove initially complete before allowing destructive processing.
			if _, err = tx.Exec(ctx, `SET CONSTRAINTS ALL IMMEDIATE`); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 12; i++ {
				if _, err = tx.Exec(ctx, `SELECT * FROM cheesetrap.retention_cleanup($1,1)`, now); err != nil {
					t.Fatal(err)
				}
			}
			var remaining int
			if err = tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM cheesetrap.events WHERE ingestion_seq BETWEEN 2001 AND 2005)+(SELECT count(*) FROM cheesetrap.detection_results WHERE detection_id='60000000-0000-4000-8000-000000000901')`).Scan(&remaining); err != nil || remaining != 0 {
				t.Fatalf("cleanup did not converge %d: %v", remaining, err)
			}
			var snapshot string
			if err = tx.QueryRow(ctx, `SELECT jsonb_build_object('copies',(SELECT jsonb_agg(to_jsonb(e) ORDER BY event_id) FROM cheesetrap.report_evidence e WHERE report_id='40000000-0000-4000-8000-000000000901'),'revision',(SELECT to_jsonb(r) FROM cheesetrap.report_revisions r WHERE revision_id='50000000-0000-4000-8000-000000000901'),'events',(SELECT jsonb_agg(event_id ORDER BY event_id) FROM cheesetrap.events WHERE ingestion_seq BETWEEN 2001 AND 2005))::text`).Scan(&snapshot); err != nil {
				t.Fatal(err)
			}
			if format == "legacy" {
				oracle = snapshot
			} else if snapshot != oracle {
				t.Fatal("legacy and chunk final evidence/copy states differ")
			}
			if format == "chunks-v1" {
				if err := tx.Commit(ctx); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
