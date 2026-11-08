package reporting

import (
	"context"
	"encoding/json"
	"strconv"
	"time"

	"cheesetrap/internal/enrichment"
	"cheesetrap/internal/store/db"
	"github.com/jackc/pgx/v5/pgxpool"
)

type ContactRefreshService struct {
	pool     *pgxpool.Pool
	contacts *enrichment.Service
}

func NewContactRefreshService(pool *pgxpool.Pool) *ContactRefreshService {
	return &ContactRefreshService{pool: pool, contacts: enrichment.NewService(pool)}
}

// Process performs registry work outside the transaction. The durable request,
// aggregate version, revision, active request and settings version all fence its
// result. Retries of a terminal request are no-ops, including stale old workers.
func (s *ContactRefreshService) Process(ctx context.Context, id string) error {
	if s == nil || s.pool == nil || !uuid(id).Valid {
		return ErrRevisionInput
	}
	var report, source, status string
	var requested time.Time
	var current bool
	err := s.pool.QueryRow(ctx, `SELECT f.report_id::text,host(r.source_ip),f.status,f.created_at,
 (f.status='queued' AND r.state IN ('held','needs_review') AND r.version=f.expected_version AND r.current_revision_id=f.revision_id AND r.active_refresh_id=f.request_id AND f.settings_version=(SELECT version FROM cheesetrap.settings WHERE key='review_policy'))
 FROM cheesetrap.contact_refresh_requests f JOIN cheesetrap.reports r USING(report_id) WHERE f.request_id=$1`, id).Scan(&report, &source, &status, &requested, &current)
	if err != nil {
		return revisionError(ctx)
	}
	if status != "queued" {
		return nil
	}
	var registry enrichment.Result
	if current {
		registry, err = s.contacts.Refresh(ctx, source, requested)
		if err != nil {
			return err
		}
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return revisionError(ctx)
	}
	defer tx.Rollback(context.Background())
	q := db.New(tx)
	r, err := q.LockReport(ctx, uuid(report))
	if err != nil {
		return revisionError(ctx)
	}
	var version, settingsVersion, latestSettings int64
	var revision, actor string
	if err = tx.QueryRow(ctx, `SELECT expected_version,revision_id::text,settings_version,admin_id::text,status FROM cheesetrap.contact_refresh_requests WHERE request_id=$1 FOR UPDATE`, id).Scan(&version, &revision, &settingsVersion, &actor, &status); err != nil {
		return revisionError(ctx)
	}
	if status != "queued" {
		return nil
	}
	if err = tx.QueryRow(ctx, `SELECT version FROM cheesetrap.settings WHERE key='review_policy'`).Scan(&latestSettings); err != nil {
		return revisionError(ctx)
	}
	action := "report_contact_refresh_superseded"
	resultRevision := ""
	resultVersion := r.Version
	if current && r.State != "rejected" && r.Version == version && r.CurrentRevisionID.String() == revision && r.ActiveRefreshID.String() == id && settingsVersion == latestSettings {
		changed, err := ChangeRevisionTx(ctx, tx, report, version, revision, RevisionChanges{}, &registry)
		if err != nil {
			return err
		}
		resultRevision = changed.RevisionID
		resultVersion = changed.Version
		status = "completed"
		action = "report_contact_refreshed"
	} else {
		status = "superseded"
	}
	if _, err = tx.Exec(ctx, `UPDATE cheesetrap.contact_refresh_requests SET status=$2,result_revision_id=nullif($3,'')::uuid,completed_at=clock_timestamp() WHERE request_id=$1`, id, status, resultRevision); err != nil {
		return revisionError(ctx)
	}
	metadata, _ := json.Marshal(map[string]string{"report_id": report, "request_id": id, "revision_id": resultRevision, "version": strconv.FormatInt(resultVersion, 10), "settings_version": strconv.FormatInt(settingsVersion, 10)})
	if err = q.AppendReviewAudit(ctx, db.AppendReviewAuditParams{AdminID: uuid(actor), Action: action, Details: metadata}); err != nil {
		return revisionError(ctx)
	}
	if err = tx.Commit(ctx); err != nil {
		return revisionError(ctx)
	}
	return nil
}
