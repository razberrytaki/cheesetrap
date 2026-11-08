//go:build integration

package retention

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

// This query-plan fixture uses the installed production DELETE, including its
// target lookup, against isolated copies of the real columns and indexes. Real
// retirement authorization, shared-root protection, and rollback are covered by
// TestChunkRetentionDatabase, TestRetentionSharedProof*, and TestRetentionLockAdmission.
func TestRetentionMemberDrainSkipsActiveMembership(t *testing.T) {
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
	proofExec(t, ctx, tx, `CREATE TABLE cheesetrap.test_member_drain_chunks (LIKE cheesetrap.evidence_chunks INCLUDING ALL);
 CREATE TABLE cheesetrap.test_member_drain_members (LIKE cheesetrap.evidence_chunk_members INCLUDING ALL);
 INSERT INTO cheesetrap.test_member_drain_chunks(chunk_id,bucket_width,bucket_no,content_hash,member_count,retired)
 SELECT ('10000000-0000-4000-8000-'||lpad(n::text,12,'0'))::uuid,256,n,repeat('a',64),256,n>512 FROM generate_series(1,526)n;
 INSERT INTO cheesetrap.test_member_drain_members(chunk_id,event_id)
 SELECT ('10000000-0000-4000-8000-'||lpad(n::text,12,'0'))::uuid,('20000000-0000-4000-8000-'||lpad((n*256+i)::text,12,'0'))::uuid
 FROM generate_series(1,526)n CROSS JOIN LATERAL generate_series(1,CASE WHEN n<=512 THEN 128 ELSE (ARRAY[0,3,17,256,64,0,128,7,1,5,0,11,6,2])[n-512] END)i;`)
	// The remaining500 retired members are spread across14 headers, including
	// empty headers and a256-member header. Active membership is much larger.
	var definition string
	if err := tx.QueryRow(ctx, `SELECT pg_get_functiondef('cheesetrap.retention_cleanup(timestamptz,integer)'::regprocedure)`).Scan(&definition); err != nil {
		t.Fatal(err)
	}
	start := strings.Index(definition, "DELETE FROM cheesetrap.evidence_chunk_members WHERE")
	if start < 0 {
		t.Fatal("installed member DELETE not found")
	}
	statement := definition[start:]
	statement = statement[:strings.Index(statement, ";")]
	statement = strings.ReplaceAll(statement, "cheesetrap.evidence_chunk_members", "cheesetrap.test_member_drain_members")
	statement = strings.ReplaceAll(statement, "cheesetrap.evidence_chunks", "cheesetrap.test_member_drain_chunks")
	statement = strings.ReplaceAll(statement, "batch_limit", "$1")
	statement += " RETURNING chunk_id::text,event_id::text"
	readKeys := func(query string, args ...any) []string {
		t.Helper()
		rows, err := tx.Query(ctx, query, args...)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var keys []string
		for rows.Next() {
			var chunk, event string
			if err := rows.Scan(&chunk, &event); err != nil {
				t.Fatal(err)
			}
			keys = append(keys, chunk+"/"+event)
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		slices.Sort(keys)
		return keys
	}
	allEligible := readKeys(`SELECT m.chunk_id::text,m.event_id::text FROM cheesetrap.test_member_drain_members m WHERE EXISTS(SELECT 1 FROM cheesetrap.test_member_drain_chunks c WHERE c.chunk_id=m.chunk_id AND c.retired)`)
	if len(allEligible) != 500 {
		t.Fatalf("fixture retired members=%d want500", len(allEligible))
	}
	for _, analyzed := range []bool{false, true} {
		if analyzed {
			proofExec(t, ctx, tx, `ANALYZE cheesetrap.test_member_drain_chunks; ANALYZE cheesetrap.test_member_drain_members`)
		}
		for _, limit := range []int{1, 64, 1000} {
			t.Run(fmt.Sprintf("analyzed_%t_limit_%d", analyzed, limit), func(t *testing.T) {
				proofExec(t, ctx, tx, "SAVEPOINT member_drain")
				got := readKeys(statement, limit)
				want := allEligible[:min(limit, len(allEligible))]
				if !slices.Equal(got, want) {
					t.Fatalf("member DELETE changed global ordered prefix: got%d want%d", len(got), len(want))
				}
				proofExec(t, ctx, tx, "ROLLBACK TO SAVEPOINT member_drain")
				var raw []byte
				if err := tx.QueryRow(ctx, "EXPLAIN (ANALYZE,BUFFERS,TIMING OFF,FORMAT JSON) "+statement, limit).Scan(&raw); err != nil {
					t.Fatal(err)
				}
				proofExec(t, ctx, tx, "ROLLBACK TO SAVEPOINT member_drain; RELEASE SAVEPOINT member_drain")
				var plans []struct{ Plan memberDrainPlan }
				if err := json.Unmarshal(raw, &plans); err != nil {
					t.Fatal(err)
				}
				visits := plans[0].Plan.memberVisits()
				// Include candidate scans AND target lookups. Allow modest planner
				// overhead, but never a scan of the65,536 unrelated active members.
				budget := float64(4 * (len(allEligible) + len(want)))
				t.Logf("full DELETE member visits=%.0f budget=%.0f eligible=%d selected=%d active=65536", visits, budget, len(allEligible), len(want))
				if visits > budget {
					t.Logf("full DELETE plan: %s", raw)
					t.Errorf("member drain scanned unrelated active membership: visits%.0f budget%.0f", visits, budget)
				}
			})
		}
	}
}

type memberDrainPlan struct {
	Relation string  `json:"Relation Name"`
	Rows     float64 `json:"Actual Rows"`
	Loops    float64 `json:"Actual Loops"`
	Removed  float64 `json:"Rows Removed by Filter"`
	Plans    []memberDrainPlan
}

func (p memberDrainPlan) memberVisits() float64 {
	var total float64
	if p.Relation == "test_member_drain_members" {
		total = (p.Rows + p.Removed) * p.Loops
	}
	for _, child := range p.Plans {
		total += child.memberVisits()
	}
	return total
}
