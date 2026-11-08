//go:build integration

package retention

import (
	"context"
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

// This isolated fixture exercises the installed whole DELETE with the real
// indexes. Production guards, terminal eligibility, and rollback are separately
// exercised by TestChunkRetentionDatabase and TestRetentionDatabase.
func TestRetentionCopyDrainSharedReferenceWork(t *testing.T) {
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
	// Deterministic UUID namespaces overlap in value range but not identity.
	// Model repeated physical membership, shared refs, and orphan chunks.
	proofExec(t, ctx, tx, `CREATE TABLE cheesetrap.test_copy_drain_copies (LIKE cheesetrap.report_evidence INCLUDING ALL);
 CREATE TABLE cheesetrap.test_copy_drain_legacy (LIKE cheesetrap.detection_evidence INCLUDING ALL);
 CREATE TABLE cheesetrap.test_copy_drain_members (LIKE cheesetrap.evidence_chunk_members INCLUDING ALL);
 CREATE TABLE cheesetrap.test_copy_drain_refs (LIKE cheesetrap.detection_evidence_chunks INCLUDING ALL);
 INSERT INTO cheesetrap.test_copy_drain_members(chunk_id,event_id)
 SELECT ('10000000-0000-4000-8000-'||lpad(n::text,12,'0'))::uuid,md5('fresh-event-'||((n*31+i)%9000)::text)::uuid
 FROM generate_series(1,5000)n CROSS JOIN generate_series(1,31)i;
 INSERT INTO cheesetrap.test_copy_drain_refs(detection_id,bucket_no,chunk_id)
 SELECT ('40000000-0000-4000-8000-'||lpad(i::text,12,'0'))::uuid,n,('10000000-0000-4000-8000-'||lpad(n::text,12,'0'))::uuid
 FROM generate_series(1,4250)n CROSS JOIN generate_series(1,70)i;
 INSERT INTO cheesetrap.test_copy_drain_copies(event_id,report_id,snapshot)
 SELECT md5('expired-copy-'||n::text)::uuid,'50000000-0000-4000-8000-000000000001','{}' FROM generate_series(1,4650)n;
 ANALYZE cheesetrap.test_copy_drain_copies; ANALYZE cheesetrap.test_copy_drain_legacy;
 ANALYZE cheesetrap.test_copy_drain_members; ANALYZE cheesetrap.test_copy_drain_refs;`)
	statement := installedCopyDrainSQL(t, ctx, tx)
	proofExec(t, ctx, tx, "PREPARE copy_drain_plan(uuid,integer) AS "+statement)
	for _, mode := range []string{"force_custom_plan", "force_generic_plan"} {
		t.Run(mode, func(t *testing.T) {
			proofExec(t, ctx, tx, "SET LOCAL plan_cache_mode="+mode)
			proofExec(t, ctx, tx, "SAVEPOINT copy_drain")
			var raw []byte
			if err := tx.QueryRow(ctx, `EXPLAIN (ANALYZE,BUFFERS,TIMING OFF,FORMAT JSON) EXECUTE copy_drain_plan('50000000-0000-4000-8000-000000000001',1000)`).Scan(&raw); err != nil {
				t.Fatal(err)
			}
			var remaining int
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM cheesetrap.test_copy_drain_copies`).Scan(&remaining); err != nil {
				t.Fatal(err)
			}
			proofExec(t, ctx, tx, "ROLLBACK TO SAVEPOINT copy_drain; RELEASE SAVEPOINT copy_drain")
			if remaining != 3650 {
				t.Fatalf("deleted %d copies, want bounded 1000", 4650-remaining)
			}
			var plans []struct{ Plan copyDrainPlan }
			if err := json.Unmarshal(raw, &plans); err != nil {
				t.Fatal(err)
			}
			visits, peak, _ := plans[0].Plan.work()
			// Permit physical scans of the membership, references, and copy tables,
			// including target lookups. Shared logical membership must not be expanded.
			budget := float64(4 * (155000 + 297500 + 4650))
			t.Logf("whole DELETE physical visits=%.0f membership-related peak=%.0f budget=%.0f logical members=9222500", visits, peak, budget)
			if visits > budget || peak > budget {
				t.Logf("whole DELETE plan: %s", raw)
				t.Errorf("copy protection expanded shared membership: visits=%.0f peak=%.0f budget=%.0f", visits, peak, budget)
			}
		})
	}
}

func installedCopyDrainSQL(t *testing.T, ctx context.Context, tx pgx.Tx) string {
	t.Helper()
	var definition string
	if err := tx.QueryRow(ctx, `SELECT pg_get_functiondef('cheesetrap.retention_cleanup(timestamptz,integer)'::regprocedure)`).Scan(&definition); err != nil {
		t.Fatal(err)
	}
	start := strings.Index(definition, "DELETE FROM cheesetrap.report_evidence WHERE")
	if start < 0 {
		t.Fatal("installed report-copy DELETE not found")
	}
	statement := definition[start:]
	end := strings.Index(statement, ";")
	if end < 0 {
		t.Fatal("installed report-copy DELETE terminator missing")
	}
	statement = statement[:end]
	for _, pair := range [][2]string{{"report_evidence", "copies"}, {"detection_evidence_chunks", "refs"}, {"evidence_chunk_members", "members"}, {"detection_evidence", "legacy"}} {
		statement = strings.ReplaceAll(statement, "cheesetrap."+pair[0], "cheesetrap.test_copy_drain_"+pair[1])
	}
	statement = strings.ReplaceAll(statement, "rid", "$1")
	statement = strings.ReplaceAll(statement, "batch_limit", "$2")
	return statement + " RETURNING event_id::text"
}

type copyDrainPlan struct {
	Relation string  `json:"Relation Name"`
	Rows     float64 `json:"Actual Rows"`
	Loops    float64 `json:"Actual Loops"`
	Removed  float64 `json:"Rows Removed by Filter"`
	Plans    []copyDrainPlan
}

func (p copyDrainPlan) work() (visits, peak float64, membership bool) {
	membership = p.Relation == "test_copy_drain_members" || p.Relation == "test_copy_drain_refs"
	if strings.HasPrefix(p.Relation, "test_copy_drain_") {
		visits = (p.Rows + p.Removed) * p.Loops
	}
	for _, child := range p.Plans {
		v, k, m := child.work()
		visits += v
		peak = max(peak, k)
		membership = membership || m
	}
	if membership {
		peak = max(peak, p.Rows*p.Loops)
	}
	return
}

// Eligibility is global across root references: either representation protects
// a copy, while orphan physical members alone do not. The real-root active and
// retiring transitions are exercised by TestChunkRetentionDatabase.
func TestRetentionCopyDrainProtectionAndBound(t *testing.T) {
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
	proofExec(t, ctx, tx, `CREATE TABLE cheesetrap.test_copy_drain_copies (LIKE cheesetrap.report_evidence INCLUDING ALL);
 CREATE TABLE cheesetrap.test_copy_drain_legacy (LIKE cheesetrap.detection_evidence INCLUDING ALL);
 CREATE TABLE cheesetrap.test_copy_drain_members (LIKE cheesetrap.evidence_chunk_members INCLUDING ALL);
 CREATE TABLE cheesetrap.test_copy_drain_refs (LIKE cheesetrap.detection_evidence_chunks INCLUDING ALL);
 INSERT INTO cheesetrap.test_copy_drain_copies(event_id,report_id,snapshot)
 SELECT ('30000000-0000-4000-8000-'||lpad(n::text,12,'0'))::uuid,'50000000-0000-4000-8000-000000000001','{}' FROM generate_series(1,1108)n;
 INSERT INTO cheesetrap.test_copy_drain_copies(event_id,report_id,snapshot)
 VALUES('30000000-0000-4000-8000-000000002000','50000000-0000-4000-8000-000000000002','{}');
 INSERT INTO cheesetrap.test_copy_drain_legacy(detection_id,event_id)
 SELECT '40000000-0000-4000-8000-000000000001',('30000000-0000-4000-8000-'||lpad(n::text,12,'0'))::uuid FROM unnest(ARRAY[1,6])n;
 INSERT INTO cheesetrap.test_copy_drain_members(chunk_id,event_id)
 SELECT '10000000-0000-4000-8000-000000000001',('30000000-0000-4000-8000-'||lpad(n::text,12,'0'))::uuid FROM unnest(ARRAY[2,3,5,8])n;
 INSERT INTO cheesetrap.test_copy_drain_members(chunk_id,event_id)
 SELECT '10000000-0000-4000-8000-000000000002',('30000000-0000-4000-8000-'||lpad(n::text,12,'0'))::uuid FROM unnest(ARRAY[4,5,6])n;
 INSERT INTO cheesetrap.test_copy_drain_refs(detection_id,bucket_no,chunk_id)
 SELECT ('40000000-0000-4000-8000-'||lpad(n::text,12,'0'))::uuid,1,'10000000-0000-4000-8000-000000000001' FROM generate_series(2,4)n;`)
	// Independent original join predicate defines the exact eligible set. Event5
	// belongs to both orphan and referenced chunks, and must remain protected.
	read := func(query string, args ...any) []string {
		t.Helper()
		rows, err := tx.Query(ctx, query, args...)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var values []string
		for rows.Next() {
			var value string
			if err := rows.Scan(&value); err != nil {
				t.Fatal(err)
			}
			values = append(values, value)
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		slices.Sort(values)
		return values
	}
	want := read(`SELECT re.event_id::text FROM cheesetrap.test_copy_drain_copies re WHERE report_id='50000000-0000-4000-8000-000000000001'
 AND NOT EXISTS(SELECT 1 FROM cheesetrap.test_copy_drain_legacy de WHERE de.event_id=re.event_id)
 AND NOT EXISTS(SELECT 1 FROM cheesetrap.test_copy_drain_members m JOIN cheesetrap.test_copy_drain_refs r USING(chunk_id) WHERE m.event_id=re.event_id)`)
	if len(want) != 1102 {
		t.Fatalf("eligible fixture=%d want1102", len(want))
	}
	statement := installedCopyDrainSQL(t, ctx, tx)
	var got []string
	for pass := 0; pass < 4; pass++ {
		batch := read(statement, "50000000-0000-4000-8000-000000000001", 1000)
		if len(batch) > 1000 {
			t.Fatalf("unbounded copy deletion: %d", len(batch))
		}
		got = append(got, batch...)
		if len(batch) == 0 {
			break
		}
	}
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Fatalf("deleted copies differ from original global protection oracle: got%d want%d", len(got), len(want))
	}
	remaining := read(`SELECT event_id::text FROM cheesetrap.test_copy_drain_copies ORDER BY event_id`)
	expected := []string{"30000000-0000-4000-8000-000000000001", "30000000-0000-4000-8000-000000000002", "30000000-0000-4000-8000-000000000003", "30000000-0000-4000-8000-000000000005", "30000000-0000-4000-8000-000000000006", "30000000-0000-4000-8000-000000000008", "30000000-0000-4000-8000-000000002000"}
	if !slices.Equal(remaining, expected) {
		t.Fatalf("protected/other-report copies changed: %v", remaining)
	}
}
