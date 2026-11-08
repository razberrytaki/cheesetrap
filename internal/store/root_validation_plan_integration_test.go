//go:build integration

package store_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

// Run the installed complete aggregate, not just its inner member lookup. LIKE
// tables preserve columns/indexes while allowing malformed proof shapes for
// output parity. TestEvidenceChunkStorage exercises actual deferred guards.
func TestRootValidationVisitsOnlyReferencedChunks(t *testing.T) {
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
	exec(`CREATE TABLE cheesetrap.test_root_plan_headers (LIKE cheesetrap.evidence_chunks INCLUDING ALL);
 CREATE TABLE cheesetrap.test_root_plan_members (LIKE cheesetrap.evidence_chunk_members INCLUDING ALL);
 CREATE TABLE cheesetrap.test_root_plan_refs (LIKE cheesetrap.detection_evidence_chunks INCLUDING ALL);
 INSERT INTO cheesetrap.test_root_plan_headers(chunk_id,bucket_width,bucket_no,content_hash,member_count)
 SELECT ('10000000-0000-4000-8000-'||lpad(n::text,12,'0'))::uuid,128,n,repeat('a',64),128 FROM generate_series(1,512)n;
 INSERT INTO cheesetrap.test_root_plan_members(chunk_id,event_id)
 SELECT ('10000000-0000-4000-8000-'||lpad(n::text,12,'0'))::uuid,md5((n*128+i)::text)::uuid FROM generate_series(1,512)n CROSS JOIN generate_series(1,128)i;
 INSERT INTO cheesetrap.test_root_plan_refs(detection_id,bucket_no,chunk_id)
 SELECT ('20000000-0000-4000-8000-'||lpad(i::text,12,'0'))::uuid,n,('10000000-0000-4000-8000-'||lpad(n::text,12,'0'))::uuid FROM generate_series(1,512)n CROSS JOIN generate_series(1,128)i;
 INSERT INTO cheesetrap.test_root_plan_headers(chunk_id,bucket_width,bucket_no,content_hash,member_count)
 SELECT ('10000000-0000-4000-8000-'||lpad(n::text,12,'0'))::uuid,CASE WHEN n IN(514,515) THEN 64 WHEN n=513 THEN 256 ELSE 128 END,n,repeat('a',64),1 FROM generate_series(513,516)n;
 INSERT INTO cheesetrap.test_root_plan_members(chunk_id,event_id)
 SELECT ('10000000-0000-4000-8000-'||lpad(c::text,12,'0'))::uuid,('30000000-0000-4000-8000-'||lpad(e::text,12,'0'))::uuid FROM (VALUES(514,1),(514,2),(515,2),(515,3),(515,4),(516,5),(516,6))v(c,e);
 INSERT INTO cheesetrap.test_root_plan_refs(detection_id,bucket_no,chunk_id)
 SELECT ('90000000-0000-4000-8000-'||lpad(r::text,12,'0'))::uuid,c,('10000000-0000-4000-8000-'||lpad(c::text,12,'0'))::uuid FROM (VALUES(1,1),(1,2),(1,513),(2,514),(2,515),(3,514),(3,516),(4,513),(4,514),(5,514),(5,999),(6,513),(6,999))v(r,c);`)
	var definition string
	if err := tx.QueryRow(ctx, `SELECT pg_get_functiondef('cheesetrap.validate_evidence_root()'::regprocedure)`).Scan(&definition); err != nil {
		t.Fatal(err)
	}
	// The final branch retains the historical v1 proof and its query-plan
	// contract; the new v2 branch is exercised by the bounded-memory tests.
	start := strings.LastIndex(definition, "SELECT count(*),count(DISTINCT m.event_id)")
	if start < 0 {
		t.Fatal("installed root aggregate missing")
	}
	statement := definition[start:]
	statement = statement[:strings.Index(statement, ";")]
	statement = strings.ReplaceAll(statement, "INTO n,unique_n,widths,ids", "")
	statement = strings.ReplaceAll(statement, "r.detection_id", "$1")
	for _, pair := range [][2]string{{"detection_evidence_chunks", "refs"}, {"evidence_chunk_members", "members"}, {"evidence_chunks", "headers"}} {
		statement = strings.ReplaceAll(statement, "cheesetrap."+pair[0], "cheesetrap.test_root_plan_"+pair[1])
	}
	oracle := `SELECT count(*),count(DISTINCT m.event_id),count(DISTINCT c.bucket_width),array_agg(m.event_id ORDER BY m.event_id) FROM cheesetrap.test_root_plan_refs d JOIN cheesetrap.test_root_plan_headers c USING(chunk_id) JOIN cheesetrap.test_root_plan_members m USING(chunk_id) WHERE d.detection_id=$1`
	read := func(sql, id string) rootProofOutput {
		t.Helper()
		var out rootProofOutput
		q := `WITH proof(n,u,w,ids) AS (` + sql + `) SELECT n,u,w,ids::text[],cheesetrap.evidence_set_hash(ids) FROM proof`
		if err := tx.QueryRow(ctx, q, id).Scan(&out.Rows, &out.Unique, &out.Widths, &out.IDs, &out.Hash); err != nil {
			t.Fatal(err)
		}
		return out
	}
	cases := []struct {
		name                       string
		rows, unique, widths, refs int64
	}{
		{"normal_with_empty_other_width", 256, 256, 1, 3},
		{"duplicate_across_chunks", 5, 4, 1, 2},
		{"mixed_widths", 4, 4, 2, 2},
		{"empty_header_ignored", 2, 2, 1, 2},
		{"missing_header_ignored", 2, 2, 1, 2},
		{"no_members", 0, 0, 0, 2},
	}
	for _, analyzed := range []bool{false, true} {
		if analyzed {
			exec(`ANALYZE cheesetrap.test_root_plan_headers; ANALYZE cheesetrap.test_root_plan_members; ANALYZE cheesetrap.test_root_plan_refs`)
		}
		exec("PREPARE root_validation_work(uuid) AS " + statement)
		for _, mode := range []string{"force_custom_plan", "force_generic_plan"} {
			exec("SET LOCAL plan_cache_mode=" + mode)
			for index, tc := range cases {
				t.Run(fmt.Sprintf("analyzed_%t/%s/%s", analyzed, mode, tc.name), func(t *testing.T) {
					id := fmt.Sprintf("90000000-0000-4000-8000-%012d", index+1)
					want, got := read(oracle, id), read(statement, id)
					if want.Rows != tc.rows || want.Unique != tc.unique || want.Widths != tc.widths {
						t.Fatalf("oracle fixture wrong: %+v", want)
					}
					if !reflect.DeepEqual(got, want) {
						t.Fatalf("full proof changed: got%+v want%+v", got, want)
					}
					var raw []byte
					if err := tx.QueryRow(ctx, `EXPLAIN (ANALYZE,BUFFERS,TIMING OFF,FORMAT JSON) EXECUTE root_validation_work('`+id+`')`).Scan(&raw); err != nil {
						t.Fatal(err)
					}
					var plans []struct{ Plan rootProofPlan }
					if err := json.Unmarshal(raw, &plans); err != nil {
						t.Fatal(err)
					}
					visits := plans[0].Plan.visits()
					memberBudget, lookupBudget := float64(4*(tc.rows+tc.refs+1)), float64(4*(tc.refs+1))
					t.Logf("aggregate work headers=%.0f members=%.0f refs=%.0f actual_members=%d", visits[0], visits[1], visits[2], tc.rows)
					if visits[0] > lookupBudget || visits[1] > memberBudget || visits[2] > lookupBudget {
						t.Logf("whole aggregate plan: %s", raw)
						t.Errorf("root proof visited unrelated physical sets: work=%v header/ref budget%.0f member budget%.0f", visits, lookupBudget, memberBudget)
					}
				})
			}
		}
		exec("DEALLOCATE root_validation_work")
	}
}

type rootProofOutput struct {
	Rows, Unique, Widths int64
	IDs                  []string
	Hash                 *string
}
type rootProofPlan struct {
	Relation string  `json:"Relation Name"`
	Rows     float64 `json:"Actual Rows"`
	Loops    float64 `json:"Actual Loops"`
	Removed  float64 `json:"Rows Removed by Filter"`
	Plans    []rootProofPlan
}

func (p rootProofPlan) visits() (out [3]float64) {
	for i, name := range []string{"test_root_plan_headers", "test_root_plan_members", "test_root_plan_refs"} {
		if p.Relation == name {
			out[i] = (p.Rows + p.Removed) * p.Loops
		}
	}
	for _, child := range p.Plans {
		v := child.visits()
		for i := range out {
			out[i] += v[i]
		}
	}
	return
}
