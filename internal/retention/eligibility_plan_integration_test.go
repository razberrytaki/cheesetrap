//go:build integration

package retention

import (
	"context"
	"encoding/json"
	"github.com/jackc/pgx/v5"
	"os"
	"strings"
	"testing"
)

// Assert work rather than a machine-dependent duration: recent roots cannot
// retire, so cleanup must not expand their potentially huge exact evidence sets.
func TestRecentRetentionDoesNotExpandEvidence(t *testing.T) {
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, os.Getenv("CHEESETRAP_TEST_RETENTION_MIGRATION_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	exec := func(q string) {
		t.Helper()
		if _, err := tx.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO cheesetrap.sensors(sensor_id,name,engine) VALUES('10000000-0000-4000-8000-000000009901','retention-plan','cowrie');
 INSERT INTO cheesetrap.file_generations(file_generation_id,sensor_id,path,device,inode) VALUES('20000000-0000-4000-8000-000000009901','10000000-0000-4000-8000-000000009901','/retention-plan',1,1);
 INSERT INTO cheesetrap.events(event_id,sensor_id,file_generation_id,byte_offset,ingestion_seq,schema_version,engine,ingested_at,service,event_type,raw_hash)
 SELECT ('00000000-0000-4000-8000-'||lpad(n::text,12,'0'))::uuid,'10000000-0000-4000-8000-000000009901','20000000-0000-4000-8000-000000009901',n,n,1,'cowrie',now(),'ssh','test',repeat('a',64) FROM generate_series(900001,900256)n;
 INSERT INTO cheesetrap.detection_results(detection_id,rule_id,rule_version,processing_event_id,processing_ingestion_seq,source_ip,window_start,window_end,evidence_hash,evidence_count,evidence_eligible,auto_approval_allowed,explanation)
 SELECT event_id,'SSH-REPEAT','plan',event_id,ingestion_seq,'8.8.4.4',ingested_at,ingested_at,repeat('a',64),256,false,false,'{}' FROM cheesetrap.events WHERE ingestion_seq BETWEEN 900001 AND 900256;
 INSERT INTO cheesetrap.detection_evidence SELECT d.detection_id,e.event_id FROM cheesetrap.detection_results d CROSS JOIN cheesetrap.events e WHERE d.rule_version='plan' AND e.ingestion_seq BETWEEN 900001 AND 900256;
 ANALYZE cheesetrap.detection_results; ANALYZE cheesetrap.events; ANALYZE cheesetrap.detection_evidence;`)
	query := activeProofSQL(t, ctx, tx)
	// Exclude all other retention fixtures, too.
	query = strings.ReplaceAll(query, "now()", "timestamptz '1900-01-01'")
	var raw []byte
	if err := tx.QueryRow(ctx, "EXPLAIN (ANALYZE,FORMAT JSON) "+query).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var plans []map[string]any
	if err := json.Unmarshal(raw, &plans); err != nil {
		t.Fatal(err)
	}
	var walk func(map[string]any)
	walk = func(node map[string]any) {
		table, _ := node["Relation Name"].(string)
		if table == "detection_evidence" || table == "evidence_chunk_members" || table == "detection_evidence_chunks" {
			if loops, _ := node["Actual Loops"].(float64); loops > 0 {
				t.Errorf("recent evidence expanded: %s executed %.0f times", table, loops)
			}
		}
		children, _ := node["Plans"].([]any)
		for _, child := range children {
			walk(child.(map[string]any))
		}
	}
	walk(plans[0]["Plan"].(map[string]any))
}
