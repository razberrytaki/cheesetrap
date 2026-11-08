package api

import (
	"context"
	"strconv"

	"cheesetrap/internal/reporting"
	"cheesetrap/internal/store/db"
	"github.com/danielgtaylor/huma/v2"
	"github.com/jackc/pgx/v5"
)

type ReportExpectation struct {
	ExpectedVersion   string `json:"expected_version" pattern:"^[1-9][0-9]*$" maxLength:"19"`
	CurrentRevisionID string `json:"current_revision_id" format:"uuid"`
}
type reportCommandInput struct {
	ID   string `path:"id" format:"uuid"`
	Key  string `header:"Idempotency-Key" required:"true" minLength:"1" maxLength:"128"`
	Body ReportExpectation
}
type selectContactInput struct {
	ID   string `path:"id" format:"uuid"`
	Key  string `header:"Idempotency-Key" required:"true" minLength:"1" maxLength:"128"`
	Body struct {
		ReportExpectation
		Recipient string `json:"recipient" minLength:"3" maxLength:"254"`
	}
}
type ReportMutation struct {
	ReportID          string `json:"report_id"`
	Version           string `json:"version"`
	CurrentRevisionID string `json:"current_revision_id"`
	State             string `json:"state"`
	RefreshRequestID  string `json:"refresh_request_id,omitempty"`
}
type reportMutationOutput struct{ Body ReportMutation }

func parseVersion(raw string) (int64, error) {
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || n < 1 || strconv.FormatInt(n, 10) != raw || n == 9223372036854775807 {
		return 0, apiError(400)
	}
	return n, nil
}
func lockExpected(ctx context.Context, tx pgx.Tx, id string, e ReportExpectation) (db.CheesetrapReport, error) {
	var empty db.CheesetrapReport
	version, err := parseVersion(e.ExpectedVersion)
	if err != nil {
		return empty, err
	}
	r, err := db.New(tx).LockReport(ctx, reviewUUID(id))
	if err != nil {
		return empty, err
	}
	var attempted bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM cheesetrap.delivery_attempts WHERE report_id=$1)`, id).Scan(&attempted); err != nil {
		return empty, err
	}
	if r.DeliveryUncertain || attempted || r.Version != version || r.CurrentRevisionID.String() != e.CurrentRevisionID || (r.State != "held" && r.State != "needs_review") {
		return empty, apiError(409)
	}
	return r, nil
}
func (s *server) registerReportCommands(a huma.API) {
	huma.Register(a, s.reviewOperation("reports-select-contact", "POST", "/api/v1/reports/{id}/select-contact"), func(ctx context.Context, in *selectContactInput) (*reportMutationOutput, error) {
		result, err := idempotent(ctx, s, in.Key, "POST", "/api/v1/reports/"+in.ID+"/select-contact", in.Body, 200, func(tx pgx.Tx) (ReportMutation, error) {
			r, err := lockExpected(ctx, tx, in.ID, in.Body.ReportExpectation)
			if err != nil {
				return ReportMutation{}, err
			}
			v, err := reporting.ChangeRevisionTx(ctx, tx, in.ID, r.Version, in.Body.CurrentRevisionID, reporting.RevisionChanges{Recipient: &in.Body.Recipient}, nil)
			if err != nil {
				return ReportMutation{}, err
			}
			result := ReportMutation{ReportID: in.ID, Version: strconv.FormatInt(v.Version, 10), CurrentRevisionID: v.RevisionID, State: v.State}
			if _, err = tx.Exec(ctx, `UPDATE cheesetrap.contact_refresh_requests SET status='superseded',completed_at=clock_timestamp() WHERE report_id=$1 AND status='queued'`, in.ID); err != nil {
				return result, err
			}
			return result, reviewAudit(ctx, tx, "report_contact_selected", result)
		})
		if err != nil {
			return nil, err
		}
		return &reportMutationOutput{Body: result}, nil
	})
	huma.Register(a, s.reviewOperation("reports-reject", "POST", "/api/v1/reports/{id}/reject"), func(ctx context.Context, in *reportCommandInput) (*reportMutationOutput, error) {
		result, err := idempotent(ctx, s, in.Key, "POST", "/api/v1/reports/"+in.ID+"/reject", in.Body, 200, func(tx pgx.Tx) (ReportMutation, error) {
			r, err := lockExpected(ctx, tx, in.ID, in.Body)
			if err != nil {
				return ReportMutation{}, err
			}
			if _, err = tx.Exec(ctx, `UPDATE cheesetrap.reports SET version=version+1,state='rejected',active_refresh_id=NULL WHERE report_id=$1`, in.ID); err != nil {
				return ReportMutation{}, err
			}
			if _, err = tx.Exec(ctx, `UPDATE cheesetrap.contact_refresh_requests SET status='superseded',completed_at=clock_timestamp() WHERE report_id=$1 AND status='queued'`, in.ID); err != nil {
				return ReportMutation{}, err
			}
			result := ReportMutation{ReportID: in.ID, Version: strconv.FormatInt(r.Version+1, 10), CurrentRevisionID: r.CurrentRevisionID.String(), State: "rejected"}
			return result, reviewAudit(ctx, tx, "report_rejected", result)
		})
		if err != nil {
			return nil, err
		}
		return &reportMutationOutput{Body: result}, nil
	})
}
