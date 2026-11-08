//go:build integration

package reporting

import (
	"cheesetrap/internal/domain"
	"cheesetrap/internal/enrichment"
	"cheesetrap/internal/store/db"
	"context"
	"encoding/json"
	"github.com/jackc/pgx/v5"
	"time"
)

// SeedRevisionTx supplies complete public-address evidence without any network.
func SeedRevisionTx(ctx context.Context, tx pgx.Tx, change func(*domain.ReportRevision)) (domain.ReportRevision, string, error) {
	var r domain.ReportRevision
	var actor, window string
	err := tx.QueryRow(ctx, `WITH inserted AS (INSERT INTO cheesetrap.admins(username,password_hash) VALUES(gen_random_uuid()::text,'test-only') ON CONFLICT DO NOTHING RETURNING admin_id) SELECT admin_id::text FROM inserted UNION ALL SELECT admin_id::text FROM cheesetrap.admins LIMIT 1`).Scan(&actor)
	if err != nil {
		return r, actor, err
	}
	err = tx.QueryRow(ctx, `INSERT INTO cheesetrap.report_windows(start_at,end_at,settings_version,state,sealed_seq,sealed_at,ready_at) VALUES(clock_timestamp()-interval '2 hours',clock_timestamp()-interval '1 hour',1,'ready',0,clock_timestamp(),clock_timestamp()) RETURNING window_id::text`).Scan(&window)
	if err != nil {
		return r, actor, err
	}
	err = tx.QueryRow(ctx, `INSERT INTO cheesetrap.reports(window_id,source_ip) VALUES($1,'1.1.1.1') RETURNING report_id::text`, window).Scan(&r.ReportID)
	if err != nil {
		return r, actor, err
	}
	var now time.Time
	if err = tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return r, actor, err
	}
	registry := enrichment.Result{SchemaVersion: 1, Address: "1.1.1.1", LookupSucceeded: true, QueriedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), Candidates: []enrichment.Contact{{Email: "abuse@example.net", Role: "abuse", Sources: []enrichment.Source{{Role: "abuse", Method: "rdap", SourceURL: "https://registry.example/ip/1.1.1.1", NetworkStart: "1.1.1.0", NetworkEnd: "1.1.1.255"}}}}}
	raw, _ := json.Marshal(registry)
	r.Version = 1
	r.Subject = "test report"
	r.Body = "test evidence"
	r.ReplyTo = "operator@example.org"
	r.Snapshot = domain.ReportSnapshot{WindowID: window, SourceIP: "1.1.1.1", ObservedStart: now.Add(-time.Hour), ObservedEnd: now.Add(-time.Hour), Registry: raw, Evidence: []domain.ReportEvidence{{ObservedAt: now.Add(-time.Hour), DestinationIP: "8.8.8.8", DestinationPort: 22}}, Rules: []domain.ReportRule{{EvidenceEligible: true, AutoApprovalAllowed: true, Explanation: json.RawMessage(`{}`)}}}
	if change != nil {
		change(&r)
	}
	q := db.New(tx)
	if err = q.SetReportReplyTo(ctx, "operator@example.org"); err != nil {
		return r, actor, err
	}
	if err = prepareRevision(ctx, q, &r, nil); err != nil {
		return r, actor, err
	}
	err = appendRevision(ctx, q, &r, 0)
	return r, actor, err
}

func RevisionTx(ctx context.Context, tx pgx.Tx, id string) (domain.ReportRevision, error) {
	return readCurrentRevision(ctx, db.New(tx), id)
}
