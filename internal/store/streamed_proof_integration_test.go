//go:build integration

package store_test

import (
	"context"
	"github.com/jackc/pgx/v5"
	"os"
	"strings"
	"testing"
)

func TestStreamedProofRejectsIncompleteMembership(t *testing.T) {
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, os.Getenv("CHEESETRAP_TEST_PROOF_MIGRATION_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	_, err = tx.Exec(ctx, `INSERT INTO cheesetrap.sensors(sensor_id,name,engine) VALUES('10000000-0000-4000-8000-000000000998','stream-proof','cowrie');
 INSERT INTO cheesetrap.file_generations(file_generation_id,sensor_id,path,device,inode) VALUES('20000000-0000-4000-8000-000000000998','10000000-0000-4000-8000-000000000998','/stream-proof',998,998);
 INSERT INTO cheesetrap.events(event_id,sensor_id,file_generation_id,byte_offset,ingestion_seq,schema_version,engine,observed_at,source_ip,destination_ip,destination_port,service,event_type,attributes,raw_hash)
 SELECT ('00000000-0000-4000-8000-'||lpad(n::text,12,'0'))::uuid,'10000000-0000-4000-8000-000000000998','20000000-0000-4000-8000-000000000998',n,n,1,'cowrie',now(),'1.1.1.1','8.8.8.8',22,'ssh','login.failed','{}',repeat('a',64) FROM generate_series(1,257)n;
 INSERT INTO cheesetrap.detection_work SELECT 'SSH-REPEAT',event_id,ingestion_seq,observed_at,'',ARRAY[]::text[] FROM cheesetrap.events;
 INSERT INTO cheesetrap.detection_completions(ingestion_seq,event_id,rule_set_version) SELECT ingestion_seq,event_id,'1' FROM cheesetrap.events;
 UPDATE cheesetrap.processing_cursors SET ingested_seq=257,detected_seq=257`)
	if err != nil {
		t.Fatal(err)
	}
	var digest string
	if err = tx.QueryRow(ctx, `SELECT cheesetrap.evidence_chain_hash(event_id ORDER BY event_id) FROM cheesetrap.detection_work`).Scan(&digest); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"valid", "wrong_hash", "wrong_count", "missing_member"} {
		t.Run(kind, func(t *testing.T) {
			sub, err := tx.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer sub.Rollback(ctx)
			hash, count := digest, 257
			if kind == "wrong_hash" {
				hash = strings.Repeat("0", 64)
			}
			if kind == "wrong_count" {
				count++
			}
			if kind == "missing_member" {
				if _, err = sub.Exec(ctx, `DELETE FROM cheesetrap.detection_work WHERE ingestion_seq=128`); err != nil {
					t.Fatal(err)
				}
			}
			var root string
			err = sub.QueryRow(ctx, `INSERT INTO cheesetrap.detection_results(rule_id,rule_version,processing_event_id,processing_ingestion_seq,source_ip,window_start,window_end,evidence_hash,evidence_count,evidence_eligible,auto_approval_allowed,explanation,evidence_representation,evidence_hash_scheme)
 VALUES('SSH-REPEAT','1','00000000-0000-4000-8000-000000000257',257,'1.1.1.1',now()-interval '10 minutes',now(),$1,$2,true,true,'{}','chunks-v1','sha256-chain-v2') RETURNING detection_id::text`, hash, count).Scan(&root)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = sub.Exec(ctx, `SELECT cheesetrap.attach_detection_work($1,'SSH-REPEAT',now()-interval '10 minutes',now())`, root); err != nil {
				t.Fatal(err)
			}
			_, err = sub.Exec(ctx, `SET CONSTRAINTS ALL IMMEDIATE`)
			if kind == "valid" && err != nil {
				t.Fatal("valid multi-bucket proof", err)
			}
			if kind != "valid" && (err == nil || !strings.Contains(err.Error(), "incomplete_evidence_root")) {
				t.Fatal("invalid proof not rejected by root validation", kind, err)
			}
		})
	}
}
