//go:build integration

package reporting

import (
	"cheesetrap/internal/domain"
	"context"
	"encoding/json"
	"github.com/jackc/pgx/v5/pgxpool"
)

// SeedLegacyRevision constructs a synthetic review-ready revision solely
// for transaction tests. It does not substitute for M3-02 preflight tests.
func SeedLegacyRevision(ctx context.Context, pool *pgxpool.Pool, ready ...bool) (id, revision, digest, admin string, err error) {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return
	}
	defer tx.Rollback(ctx)
	err = tx.QueryRow(ctx, `WITH inserted AS (INSERT INTO cheesetrap.admins(username,password_hash) VALUES(gen_random_uuid()::text,'test-only') ON CONFLICT DO NOTHING RETURNING admin_id) SELECT admin_id::text FROM inserted UNION ALL SELECT admin_id::text FROM cheesetrap.admins LIMIT 1`).Scan(&admin)
	if err != nil {
		return
	}
	state := "ready"
	if len(ready) > 0 && !ready[0] {
		state = "sealed"
	}
	var window string
	err = tx.QueryRow(ctx, `INSERT INTO cheesetrap.report_windows(start_at,end_at,settings_version,state,sealed_seq,sealed_at,ready_at) VALUES(clock_timestamp()-interval '2 hours',clock_timestamp()-interval '1 hour',1,$1,0,clock_timestamp(),CASE WHEN $1='ready' THEN clock_timestamp() ELSE NULL END) RETURNING window_id::text`, state).Scan(&window)
	if err != nil {
		return
	}
	err = tx.QueryRow(ctx, `INSERT INTO cheesetrap.reports(window_id,source_ip) VALUES($1,'1.1.1.1') RETURNING report_id::text`, window).Scan(&id)
	if err != nil {
		return
	}
	r := domain.ReportRevision{ReportID: id, Version: 1, State: "needs_review", Recipient: "abuse@example.net", ReplyTo: "operator@example.org", Subject: "report", Body: "test report", HoldReasons: []string{}, Snapshot: domain.ReportSnapshot{WindowID: window, SourceIP: "1.1.1.1"}}
	digest, err = ContentDigest(r)
	if err != nil {
		return
	}
	snapshot, _ := json.Marshal(r.Snapshot)
	err = tx.QueryRow(ctx, `INSERT INTO cheesetrap.report_revisions(report_id,version,snapshot,subject,body,recipient,reply_to,hold_reasons,state,auto_approval_allowed,body_edited,content_digest) VALUES($1,1,$2,$3,$4,$5,$6,'{}','needs_review',false,false,$7) RETURNING revision_id::text`, id, snapshot, r.Subject, r.Body, r.Recipient, r.ReplyTo, digest).Scan(&revision)
	if err != nil {
		return
	}
	_, err = tx.Exec(ctx, `UPDATE cheesetrap.reports SET version=1,current_revision_id=$2,state='needs_review' WHERE report_id=$1`, id, revision)
	if err != nil {
		return
	}
	err = tx.Commit(ctx)
	return
}
