package api

import (
	"context"
	"strconv"

	"cheesetrap/internal/auth"
	"cheesetrap/internal/jobs"
	"github.com/danielgtaylor/huma/v2"
	"github.com/jackc/pgx/v5"
)

func (s *server) registerContactRefresh(a huma.API) {
	op := s.reviewOperation("reports-refresh-contact", "POST", "/api/v1/reports/{id}/refresh-contact")
	op.DefaultStatus = 202
	huma.Register(a, op, func(ctx context.Context, in *reportCommandInput) (*reportMutationOutput, error) {
		result, err := idempotent(ctx, s, in.Key, "POST", "/api/v1/reports/"+in.ID+"/refresh-contact", in.Body, 202, func(tx pgx.Tx) (ReportMutation, error) {
			r, err := lockExpected(ctx, tx, in.ID, in.Body)
			if err != nil {
				return ReportMutation{}, err
			}
			actor := ctx.Value(identityKey).(auth.Identity)
			var request string
			if err = tx.QueryRow(ctx, `INSERT INTO cheesetrap.contact_refresh_requests(report_id,expected_version,revision_id,settings_version,admin_id) SELECT $1,$2,$3,version,$4 FROM cheesetrap.settings WHERE key='review_policy' RETURNING request_id::text`, in.ID, r.Version+1, in.Body.CurrentRevisionID, actor.AdminID).Scan(&request); err != nil {
				return ReportMutation{}, err
			}
			if _, err = tx.Exec(ctx, `UPDATE cheesetrap.contact_refresh_requests SET status='superseded',completed_at=clock_timestamp() WHERE report_id=$1 AND request_id<>$2 AND status='queued'`, in.ID, request); err != nil {
				return ReportMutation{}, err
			}
			if _, err = tx.Exec(ctx, `UPDATE cheesetrap.reports SET version=version+1,active_refresh_id=$2 WHERE report_id=$1`, in.ID, request); err != nil {
				return ReportMutation{}, err
			}
			producer, err := jobs.NewProducer(s.pool)
			if err != nil {
				return ReportMutation{}, err
			}
			if _, err = producer.InsertTx(ctx, tx, jobs.ContactRefreshArgs{RequestID: request}, nil); err != nil {
				return ReportMutation{}, err
			}
			result := ReportMutation{ReportID: in.ID, Version: strconv.FormatInt(r.Version+1, 10), CurrentRevisionID: in.Body.CurrentRevisionID, State: r.State, RefreshRequestID: request}
			return result, reviewAudit(ctx, tx, "report_contact_refresh_requested", result)
		})
		if err != nil {
			return nil, err
		}
		return &reportMutationOutput{Body: result}, nil
	})
}
