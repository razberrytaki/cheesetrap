//go:build integration

package reporting

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"cheesetrap/internal/store"
	"cheesetrap/internal/store/db"
	"github.com/jackc/pgx/v5/pgtype"
)

func TestReportRevisionBindingRoundTrip(t *testing.T) {
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
	var reportID pgtype.UUID
	if err := tx.QueryRow(ctx, `WITH w AS (INSERT INTO cheesetrap.report_windows(start_at,end_at,settings_version,state,sealed_seq,sealed_at,ready_at) VALUES('2003-01-01','2003-01-02',1,'ready',0,'2003-01-02','2003-01-02') RETURNING window_id) INSERT INTO cheesetrap.reports(window_id,source_ip) SELECT window_id,'1.1.1.1' FROM w RETURNING report_id`).Scan(&reportID); err != nil {
		t.Fatal(err)
	}
	// Distinct values catch swaps between arguments sharing PostgreSQL types.
	// Both boolean orientations are exercised; JSONB retains exact large numbers.
	for i := range 2 {
		p := db.AppendReportRevisionParams{ReportID: reportID, Version: int64(i + 1), Snapshot: []byte(`{"unique":"snapshot","large":9007199254740993,"evidence":[],"rules":[]}`), Subject: "distinct subject", Body: "distinct body\nsecond line", Recipient: "recipient@example.test", ReplyTo: "reply@example.test", HoldReasons: []string{"contact_missing", "evidence_incomplete"}, State: "held", AutoApprovalAllowed: i == 0, BodyEdited: i != 0, ContentDigest: strings.Repeat("a", 64)}
		id, err := db.New(tx).AppendReportRevision(ctx, p)
		if err != nil {
			t.Fatal(err)
		}
		var identical bool
		// This independent column-to-value order must not track SQL placeholder edits.
		if err := tx.QueryRow(ctx, `SELECT report_id=$2 AND version=$3 AND snapshot=$4::jsonb AND subject=$5 AND body=$6 AND recipient=$7 AND reply_to=$8 AND hold_reasons=$9::text[] AND state=$10 AND auto_approval_allowed=$11 AND body_edited=$12 AND content_digest=$13 FROM cheesetrap.report_revisions WHERE revision_id=$1`, id, p.ReportID, p.Version, p.Snapshot, p.Subject, p.Body, p.Recipient, p.ReplyTo, p.HoldReasons, p.State, p.AutoApprovalAllowed, p.BodyEdited, p.ContentDigest).Scan(&identical); err != nil || !identical {
			t.Fatalf("revision %d changed a stored field: equal=%v err=%v", i+1, identical, err)
		}
	}
}
