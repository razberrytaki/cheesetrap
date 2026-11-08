//go:build integration

package store_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

// Explain the installed function body: EXPLAIN of its caller hides SQL-function
// work. LIKE preserves the actual indexes without requiring unrelated fixtures
// to satisfy deferred proof guards. API integration tests exercise those guards.
// These disposable read-plan fixtures are UNLOGGED: their bulk graph must not
// fill the shared test database WAL, and crash durability is not under test.
func TestEventClassifierVisitsOnlyMatchingMembership(t *testing.T) {
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
	tables := [][2]string{{"event_evidence_history", "history"}, {"detection_evidence_chunks", "refs"}, {"evidence_chunk_members", "members"}, {"detection_evidence", "legacy"}, {"detection_results", "roots"}}
	for _, pair := range tables {
		exec("CREATE UNLOGGED TABLE cheesetrap.test_event_plan_" + pair[1] + " (LIKE cheesetrap." + pair[0] + " INCLUDING ALL)")
	}
	exec(`INSERT INTO cheesetrap.test_event_plan_roots(detection_id,rule_id,rule_version,processing_event_id,processing_ingestion_seq,source_ip,window_start,window_end,evidence_hash,evidence_count,evidence_eligible,auto_approval_allowed,explanation,evidence_representation,evidence_state)
 SELECT md5('root'||n)::uuid,'SSH-REPEAT','1',md5('process'||n)::uuid,CASE WHEN n=8194 THEN 80 ELSE 100 END,'192.0.2.1',now(),now(),repeat('a',64),1,true,false,'{}',CASE WHEN n=8194 THEN 'legacy' ELSE 'chunks-v1' END,CASE WHEN n=8195 THEN 'retiring' ELSE 'active' END FROM generate_series(1,8195)n;
 INSERT INTO cheesetrap.test_event_plan_refs(detection_id,bucket_no,chunk_id)
 SELECT md5('root'||n)::uuid,c,md5('chunk'||c)::uuid FROM generate_series(1,8192)n CROSS JOIN generate_series(1,64)c;
 INSERT INTO cheesetrap.test_event_plan_members(chunk_id,event_id) SELECT md5('chunk'||c)::uuid,md5('member'||c)::uuid FROM generate_series(1,64)c;
 INSERT INTO cheesetrap.test_event_plan_refs(detection_id,bucket_no,chunk_id) VALUES(md5('root8193')::uuid,999,md5('chunk999')::uuid),(md5('root8195')::uuid,1000,md5('chunk1000')::uuid),(md5('root8194')::uuid,1001,md5('chunk1001')::uuid);
 INSERT INTO cheesetrap.test_event_plan_members(chunk_id,event_id) VALUES(md5('chunk999')::uuid,'00000000-0000-4000-8000-000000000002'),(md5('chunk1000')::uuid,'00000000-0000-4000-8000-000000000005'),(md5('chunk1001')::uuid,'00000000-0000-4000-8000-000000000006');
 INSERT INTO cheesetrap.test_event_plan_legacy(detection_id,event_id) VALUES(md5('root8194')::uuid,'00000000-0000-4000-8000-000000000003'),(md5('root8193')::uuid,'00000000-0000-4000-8000-000000000007');
 INSERT INTO cheesetrap.test_event_plan_members(chunk_id,event_id) VALUES(md5('chunk1')::uuid,'00000000-0000-4000-8000-000000000008');
 INSERT INTO cheesetrap.test_event_plan_history VALUES('00000000-0000-4000-8000-000000000004',60),('00000000-0000-4000-8000-000000000010',0);`)
	var statement string
	if err := tx.QueryRow(ctx, `SELECT prosrc FROM pg_proc WHERE oid='cheesetrap.event_detection_result(uuid,bigint,bigint)'::regprocedure`).Scan(&statement); err != nil {
		t.Fatal(err)
	}
	for _, pair := range tables {
		statement = strings.ReplaceAll(statement, "cheesetrap."+pair[0], "cheesetrap.test_event_plan_"+pair[1])
	}
	for i, name := range []string{"id", "seq", "processed"} {
		statement = regexp.MustCompile(`\b`+name+`\b`).ReplaceAllStringFunc(statement, func(string) string { return fmt.Sprintf("$%d", i+1) })
	}
	cases := []struct {
		name               string
		id, seq, processed int
		want               string
	}{
		{"absent", 1, 1, 100, "no_match"}, {"sparse_chunk", 2, 2, 100, "evidence"}, {"chunk_after_snapshot", 2, 2, 90, "no_match"},
		{"legacy", 3, 3, 100, "evidence"}, {"legacy_after_snapshot", 3, 3, 70, "no_match"},
		{"history", 4, 4, 100, "evidence"}, {"history_after_snapshot", 4, 4, 50, "no_match"},
		{"retiring_chunk", 5, 5, 100, "no_match"}, {"wrong_chunk_representation", 6, 6, 100, "no_match"},
		{"wrong_legacy_representation", 7, 7, 100, "no_match"}, {"pending_short_circuit", 2, 101, 100, "pending"}, {"matched_fanout_after_snapshot", 8, 8, 90, "no_match"}, {"history_backfill_zero", 10, 10, 0, "pending"}, {"history_backfill_zero_processed", 10, 0, 0, "evidence"},
	}
	for _, statistics := range []string{"unanalysed", "analyzed", "stale_after_delete"} {
		if statistics == "analyzed" {
			for _, pair := range tables {
				exec("ANALYZE cheesetrap.test_event_plan_" + pair[1])
			}
		}
		if statistics == "stale_after_delete" {
			exec("DELETE FROM cheesetrap.test_event_plan_refs WHERE bucket_no BETWEEN 2 AND 60")
		}
		for _, jit := range []string{"on", "off"} {
			exec("SET LOCAL jit=" + jit)
			exec("PREPARE event_classifier_work(uuid,bigint,bigint) AS " + statement)
			for _, mode := range []string{"force_custom_plan", "force_generic_plan"} {
				exec("SET LOCAL plan_cache_mode=" + mode)
				for _, tc := range cases {
					t.Run(fmt.Sprintf("%s/jit_%s/%s/%s", statistics, jit, mode, tc.name), func(t *testing.T) {
						query := fmt.Sprintf("EXECUTE event_classifier_work('00000000-0000-4000-8000-%012d',%d,%d)", tc.id, tc.seq, tc.processed)
						var got string
						if err := tx.QueryRow(ctx, query).Scan(&got); err != nil {
							t.Fatal(err)
						}
						if got != tc.want {
							t.Fatalf("classification=%s want%s", got, tc.want)
						}
						var raw []byte
						if err := tx.QueryRow(ctx, "EXPLAIN (ANALYZE,BUFFERS,TIMING OFF,FORMAT JSON) "+query).Scan(&raw); err != nil {
							t.Fatal(err)
						}
						var plans []struct {
							Plan      eventClassifierPlan
							Execution float64 `json:"Execution Time"`
							JIT       json.RawMessage
						}
						if err := json.Unmarshal(raw, &plans); err != nil {
							t.Fatal(err)
						}
						visits := plans[0].Plan.visits()
						t.Logf("physical visits=%v execution_ms=%.3f jit=%s", visits, plans[0].Execution, plans[0].JIT)
						budget := float64(128)
						if tc.name == "matched_fanout_after_snapshot" {
							budget = 20000
						}
						if tc.want == "pending" {
							budget = 0
						}
						for _, v := range visits {
							if v > budget {
								t.Logf("installed classifier plan: %s", raw)
								t.Errorf("classifier visits unrelated evidence: %v budget%.0f", visits, budget)
								break
							}
						}
					})
				}
			}
			exec("DEALLOCATE event_classifier_work")
		}
	}
}

type eventClassifierPlan struct {
	Relation string  `json:"Relation Name"`
	Rows     float64 `json:"Actual Rows"`
	Loops    float64 `json:"Actual Loops"`
	Removed  float64 `json:"Rows Removed by Filter"`
	Plans    []eventClassifierPlan
}

func (p eventClassifierPlan) visits() (out [5]float64) {
	for i, name := range []string{"history", "legacy", "members", "refs", "roots"} {
		if p.Relation == "test_event_plan_"+name {
			out[i] = (p.Rows + p.Removed) * p.Loops
		}
	}
	for _, c := range p.Plans {
		v := c.visits()
		for i := range out {
			out[i] += v[i]
		}
	}
	return
}
