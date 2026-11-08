//go:build integration

package reporting

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"testing"
	"time"

	"cheesetrap/internal/domain"
	"cheesetrap/internal/store"
	"cheesetrap/internal/store/db"
	"github.com/jackc/pgx/v5/pgtype"
)

func TestReportEvidenceCopyBatchBounds(t *testing.T) {
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
	defer tx.Rollback(ctx)
	for _, sql := range []string{
		`CREATE TABLE cheesetrap.test_report_copy_batch_sizes(n bigint)`,
		`CREATE FUNCTION cheesetrap.test_report_copy_batch_size() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN INSERT INTO cheesetrap.test_report_copy_batch_sizes SELECT count(*) FROM new_copies; RETURN NULL; END $$`,
		`CREATE TRIGGER test_report_copy_batch_size AFTER INSERT ON cheesetrap.report_evidence REFERENCING NEW TABLE AS new_copies FOR EACH STATEMENT EXECUTE FUNCTION cheesetrap.test_report_copy_batch_size()`,
	} {
		if _, err := tx.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	var reportID pgtype.UUID
	if err := tx.QueryRow(ctx, `WITH w AS (INSERT INTO cheesetrap.report_windows(start_at,end_at,settings_version,state,sealed_seq,sealed_at,ready_at) VALUES('2002-01-01','2002-01-02',1,'ready',0,'2002-01-02','2002-01-02') RETURNING window_id) INSERT INTO cheesetrap.reports(window_id,source_ip) SELECT window_id,'1.1.1.1' FROM w RETURNING report_id`).Scan(&reportID); err != nil {
		t.Fatal(err)
	}
	evidence := make([]domain.ReportEvidence, 2501)
	for i := range evidence {
		evidence[i] = domain.ReportEvidence{EventID: fmt.Sprintf("70000000-0000-4000-8000-%012d", i), IngestionSeq: int64(i + 1)}
	}
	if err := copyReportEvidence(ctx, db.New(tx), reportID, evidence); err != nil {
		t.Fatal(err)
	}
	var sizes []int64
	if err := tx.QueryRow(ctx, `SELECT array_agg(n ORDER BY ctid) FROM cheesetrap.test_report_copy_batch_sizes`).Scan(&sizes); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(sizes, []int64{1000, 1000, 501}) {
		t.Fatalf("copy batch sizes=%v, want [1000 1000 501]", sizes)
	}
	var total, unique int
	if err := tx.QueryRow(ctx, `SELECT count(*),count(DISTINCT snapshot->>'ingestion_seq') FROM cheesetrap.report_evidence WHERE report_id=$1`, reportID).Scan(&total, &unique); err != nil || total != 2501 || unique != 2501 {
		t.Fatalf("copied total=%d unique=%d error=%v", total, unique, err)
	}

	// PostgreSQL sees the identical complete JSONB value and every copied event
	// retains all of its original fields across statement boundaries.
	snapshot := domain.ReportSnapshot{Evidence: evidence, Registry: json.RawMessage(`{"z":9007199254740993,"a":1}`)}
	oldJSON, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	newJSON, err := marshalReportSnapshot(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	var equal bool
	if err := tx.QueryRow(ctx, `SELECT $1::jsonb=$2::jsonb`, oldJSON, newJSON).Scan(&equal); err != nil || !equal {
		t.Fatal("stored JSONB snapshot changed", err)
	}
	evidenceJSON, err := json.Marshal(evidence)
	if err != nil {
		t.Fatal(err)
	}
	var different int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM cheesetrap.report_evidence r JOIN jsonb_array_elements($1::jsonb) e ON r.event_id=(e->>'event_id')::uuid WHERE r.report_id=$2 AND r.snapshot<>e`, evidenceJSON, reportID).Scan(&different); err != nil || different != 0 {
		t.Fatal("batched copy contents changed", different, err)
	}
	// A failure on the first event of batch two must undo the report and every
	// earlier copy in the caller's transaction, preserving the original owner.
	failed, err := tx.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var failedID pgtype.UUID
	if err := failed.QueryRow(ctx, `INSERT INTO cheesetrap.reports(window_id,source_ip) SELECT window_id,'9.9.9.9' FROM cheesetrap.reports WHERE report_id=$1 RETURNING report_id`, reportID).Scan(&failedID); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 1000; i++ {
		evidence[i].EventID = fmt.Sprintf("80000000-0000-4000-8000-%012d", i)
	}
	if err := copyReportEvidence(ctx, db.New(failed), failedID, evidence[:1001]); err == nil {
		t.Fatal("later batch global ownership conflict accepted")
	}
	if err := failed.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	var reports, copies, revisions, candidates int
	if err := tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM cheesetrap.reports WHERE report_id=$1),(SELECT count(*) FROM cheesetrap.report_evidence WHERE report_id=$1),(SELECT count(*) FROM cheesetrap.report_revisions WHERE report_id=$1),(SELECT count(*) FROM cheesetrap.report_candidates WHERE report_id=$1)`, failedID).Scan(&reports, &copies, &revisions, &candidates); err != nil {
		t.Fatal(err)
	}
	if reports+copies+revisions+candidates != 0 {
		t.Fatal("late batch failure left partial report state")
	}
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM cheesetrap.report_evidence WHERE report_id=$1`, reportID).Scan(&total); err != nil || total != 2501 {
		t.Fatal("conflict altered original owner", total, err)
	}
}
