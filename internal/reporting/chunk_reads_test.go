//go:build integration

package reporting

import (
	"context"
	"encoding/json"
	"net/netip"
	"testing"

	"cheesetrap/internal/store/db"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

// This fixture-only conversion preserves root IDs and every business field.
// It runs under the owner in a rolled-back transaction, never a runtime path.
func verifyChunkReadCompatibility(t *testing.T, ctx context.Context, owner *pgxpool.Pool, window string) {
	t.Helper()
	tx, err := owner.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := tx.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`ALTER TABLE cheesetrap.detection_results DISABLE TRIGGER guard_evidence_root; ALTER TABLE cheesetrap.detection_evidence_chunks DISABLE TRIGGER guard_chunk_refs`)
	q := db.New(tx)
	var w db.CheesetrapReportWindow
	if err := tx.QueryRow(ctx, `SELECT window_id,start_at,end_at FROM cheesetrap.report_windows WHERE window_id=$1`, window).Scan(&w.WindowID, &w.StartAt, &w.EndAt); err != nil {
		t.Fatal(err)
	}
	type membership struct {
		id  pgtype.UUID
		ids []pgtype.UUID
	}
	rows, err := tx.Query(ctx, `SELECT d.detection_id, array_agg(e.event_id ORDER BY e.event_id) FROM cheesetrap.detection_results d JOIN (SELECT detection_id,event_id FROM cheesetrap.detection_evidence UNION ALL SELECT r.detection_id,m.event_id FROM cheesetrap.detection_evidence_chunks r JOIN cheesetrap.evidence_chunk_members m USING(chunk_id)) e USING(detection_id) GROUP BY d.detection_id ORDER BY d.detection_id`)
	if err != nil {
		t.Fatal(err)
	}
	var roots []membership
	for rows.Next() {
		var r membership
		if err := rows.Scan(&r.id, &r.ids); err != nil {
			t.Fatal(err)
		}
		roots = append(roots, r)
	}
	rows.Close()
	if rows.Err() != nil {
		t.Fatal(rows.Err())
	}
	if len(roots) < 3 {
		t.Fatal("all-rule fixture missing")
	}
	// Historical v1 roots must still read identically across legacy/chunk/mixed
	// storage. Convert only this rolled-back fixture's hash scheme as well.
	for _, r := range roots {
		exec(`UPDATE cheesetrap.detection_results SET evidence_hash_scheme='sha256-json-v1',evidence_hash=cheesetrap.evidence_set_hash($2::uuid[]) WHERE detection_id=$1`, r.id, r.ids)
	}
	convert := func(chunk func(int) bool) {
		for i, r := range roots {
			exec(`DELETE FROM cheesetrap.detection_evidence_chunks WHERE detection_id=$1`, r.id)
			exec(`DELETE FROM cheesetrap.detection_evidence WHERE detection_id=$1`, r.id)
			format := "legacy"
			if chunk(i) {
				format = "chunks-v1"
			}
			exec(`UPDATE cheesetrap.detection_results SET evidence_representation=$2 WHERE detection_id=$1`, r.id, format)
			if chunk(i) {
				exec(`SELECT cheesetrap.store_detection_chunks($1,128,$2::uuid[])`, r.id, r.ids)
			} else {
				exec(`INSERT INTO cheesetrap.detection_evidence SELECT $1,unnest($2::uuid[])`, r.id, r.ids)
			}
		}
	}
	snapshot := func() string {
		t.Helper()
		s, err := collectEvidence(ctx, q, w, "1.1.1.1")
		if err != nil {
			t.Fatal(err)
		}
		for i := 1; i < len(s.Evidence); i++ {
			if s.Evidence[i-1].IngestionSeq >= s.Evidence[i].IngestionSeq {
				t.Fatal("evidence order/uniqueness changed")
			}
		}
		b, err := json.Marshal(s)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	convert(func(int) bool { return false })
	baseline := snapshot()
	convert(func(i int) bool { return i%2 == 0 })
	if snapshot() != baseline {
		t.Fatal("mixed-format complete snapshot differs from legacy")
	}
	convert(func(int) bool { return true })
	if snapshot() != baseline {
		t.Fatal("chunk complete snapshot differs from legacy")
	}
	// Ownership is global, including evidence assigned to another source/window.
	exec(`WITH r AS (INSERT INTO cheesetrap.reports(window_id,source_ip) VALUES($1,'9.9.9.9') RETURNING report_id) INSERT INTO cheesetrap.report_evidence SELECT e.event_id,r.report_id,'{}' FROM cheesetrap.events e CROSS JOIN r WHERE e.ingestion_seq IN (1,11)`, w.WindowID)
	convert(func(int) bool { return false })
	ownedBaseline := snapshot()
	if ownedBaseline == baseline {
		t.Fatal("ownership fixture did not change snapshot")
	}
	convert(func(i int) bool { return i%2 == 0 })
	if snapshot() != ownedBaseline {
		t.Fatal("mixed ownership/AttachedCount differs")
	}
	convert(func(int) bool { return true })
	if snapshot() != ownedBaseline {
		t.Fatal("chunk ownership/AttachedCount differs")
	}
	// Future cleanup may leave partial retiring roots: all readers must omit them.
	exec(`UPDATE cheesetrap.detection_results SET evidence_state='retiring'`)
	s, err := collectEvidence(ctx, q, w, "1.1.1.1")
	if err != nil || len(s.Rules) != 0 || len(s.Evidence) != 0 {
		t.Fatalf("retiring evidence exposed: %v", err)
	}
	ds, err := q.ListWindowDetections(ctx, w.WindowID)
	if err != nil || len(ds) != 0 {
		t.Fatalf("retiring window roots exposed: %v", err)
	}
	if _, err = q.NextDraftSource(ctx, w.WindowID); err != pgx.ErrNoRows {
		t.Fatalf("retiring source selected: %v", err)
	}
	rs, err := q.ListReportSourceDetections(ctx, db.ListReportSourceDetectionsParams{WindowID: w.WindowID, SourceIp: netip.MustParseAddr("1.1.1.1")})
	if err != nil || len(rs) != 0 {
		t.Fatal("retiring report roots exposed", err)
	}
}
