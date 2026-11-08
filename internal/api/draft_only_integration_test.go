//go:build integration

package api

import (
	"strconv"
	"testing"
)

func TestDraftOnlyAPI(t *testing.T) {
	f := newReviewFixtureDomain(t, "AUTOMATIC_API")
	id, revision := f.report("1.1.1.1")
	for _, path := range []string{"approve", "cancel", "retry", "close-unconfirmed"} {
		decodeReview(t, f.mutate("POST", "/api/v1/reports/"+id+"/"+path, "removed-"+path, map[string]any{}), 404)
	}
	decodeReview(t, f.mutate("POST", "/api/v1/settings/smtp-test", "removed-smtp", map[string]any{}), 404)
	decodeReview(t, f.get("/api/v1/deliveries"), 404)
	settings := decodeReview(t, f.get("/api/v1/settings"), 200)
	for _, body := range []map[string]any{
		{"expected_version": settings["version"], "automatic_mode": true},
		{"expected_version": settings["version"], "delivery_limits": map[string]any{"daily": 100, "recipient_daily": 20}},
	} {
		decodeReview(t, f.mutate("PATCH", "/api/v1/settings", "removed-setting", body), 422)
	}
	// Historical aggregates remain readable without reviving their sending lifecycle.
	var approval string
	if err := f.owner.QueryRow(f.ctx, `INSERT INTO cheesetrap.approvals(report_id,revision_id,content_digest,admin_id,settings_version,schedule_version,approved_at,scheduled_at) SELECT r.report_id,r.current_revision_id,v.content_digest,a.admin_id,1,1,clock_timestamp(),clock_timestamp()+interval '1 hour' FROM cheesetrap.reports r JOIN cheesetrap.report_revisions v ON v.revision_id=r.current_revision_id CROSS JOIN cheesetrap.admins a WHERE r.report_id=$1 LIMIT 1 RETURNING approval_id::text`, id).Scan(&approval); err != nil {
		t.Fatal(err)
	}
	for _, state := range []string{"queued", "sending"} {
		if _, err := f.owner.Exec(f.ctx, `UPDATE cheesetrap.reports SET state=$2,version=version+1 WHERE report_id=$1`, id, state); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.owner.Exec(f.ctx, `INSERT INTO cheesetrap.delivery_attempts(report_id,revision_id,approval_id,attempt_number,message_id,phase,result,classification,started_at,finished_at) VALUES($1,$2,$3,1,'legacy@invalid','response','sent','smtp_accepted',clock_timestamp()-interval '1 second',clock_timestamp())`, id, revision, approval); err != nil {
		t.Fatal(err)
	}
	if _, err := f.owner.Exec(f.ctx, `UPDATE cheesetrap.reports SET state='sent',version=version+1 WHERE report_id=$1`, id); err != nil {
		t.Fatal(err)
	}
	archived := decodeReview(t, f.get("/api/v1/reports/"+id), 200)
	if archived["state"] != "archived" || archived["current_revision_id"] != revision {
		t.Fatal("legacy draft read changed", archived["state"])
	}
	decodeReview(t, f.get("/api/v1/reports?state=archived"), 200)
	decodeReview(t, f.mutate("POST", "/api/v1/reports/"+id+"/reject", "archive-edit", map[string]any{"expected_version": archived["version"], "current_revision_id": revision}), 409)
	var n int
	if err := f.owner.QueryRow(f.ctx, `SELECT count(*) FROM cheesetrap_river.river_job WHERE kind IN ('deliver_report','smtp_test')`).Scan(&n); err != nil || n != 0 {
		t.Fatal("removed API queued sending", n, err)
	}
}

func TestHistoricalReviewDraftsAreArchived(t *testing.T) {
	for _, result := range []string{"unknown", "failed"} {
		t.Run(result, func(t *testing.T) {
			f := newReviewFixtureDomain(t, "AUTOMATIC_API")
			id, revision := f.report("8.8.4.4")
			var approval string
			if err := f.owner.QueryRow(f.ctx, `INSERT INTO cheesetrap.approvals(report_id,revision_id,content_digest,admin_id,settings_version,schedule_version,approved_at,scheduled_at) SELECT r.report_id,r.current_revision_id,v.content_digest,a.admin_id,1,1,clock_timestamp(),clock_timestamp()+interval '1 hour' FROM cheesetrap.reports r JOIN cheesetrap.report_revisions v ON v.revision_id=r.current_revision_id CROSS JOIN cheesetrap.admins a WHERE r.report_id=$1 LIMIT 1 RETURNING approval_id::text`, id).Scan(&approval); err != nil {
				t.Fatal(err)
			}
			for _, state := range []string{"queued", "sending"} {
				if _, err := f.owner.Exec(f.ctx, `UPDATE cheesetrap.reports SET state=$2,version=version+1 WHERE report_id=$1`, id, state); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := f.owner.Exec(f.ctx, `INSERT INTO cheesetrap.delivery_attempts(report_id,revision_id,approval_id,attempt_number,message_id,phase,result,classification,started_at,finished_at) VALUES($1,$2,$3,1,'legacy@invalid','response',$4,'smtp_interrupted',clock_timestamp()-interval '1 second',clock_timestamp())`, id, revision, approval, result); err != nil {
				t.Fatal(err)
			}
			for _, state := range []string{result, "needs_review"} {
				if _, err := f.owner.Exec(f.ctx, `UPDATE cheesetrap.reports SET state=$2,version=version+1 WHERE report_id=$1`, id, state); err != nil {
					t.Fatal(err)
				}
			}
			current := decodeReview(t, f.get("/api/v1/reports/"+id), 200)
			if current["state"] != "archived" {
				t.Errorf("historical draft state = %v, want archived", current["state"])
			}
			archived := decodeReview(t, f.get("/api/v1/reports?state=archived&source_ip=8.8.4.4"), 200)
			if len(archived["items"].([]any)) == 0 {
				t.Error("historical draft absent from archived filter")
			}
			active := decodeReview(t, f.get("/api/v1/reports?state=needs_review&source_ip=8.8.4.4"), 200)
			if len(active["items"].([]any)) != 0 {
				t.Error("historical draft appears in active review filter")
			}
			overview := decodeReview(t, f.get("/api/v1/overview"), 200)
			states := overview["operations"].(map[string]any)["report_states"].(map[string]any)
			for _, state := range []string{"held", "needs_review", "archived"} {
				listed := decodeReview(t, f.get("/api/v1/reports?limit=200&state="+state), 200)
				want := strconv.Itoa(len(listed["items"].([]any)))
				got := states[state]
				if got == nil {
					got = "0"
				}
				if got != want {
					t.Errorf("overview %s = %v, list count = %s", state, got, want)
				}
			}
			for _, action := range []string{"reject", "refresh-contact", "select-contact"} {
				body := map[string]any{"expected_version": current["version"], "current_revision_id": revision}
				if action == "select-contact" {
					body["recipient"] = "abuse@example.net"
				}
				decodeReview(t, f.mutate("POST", "/api/v1/reports/"+id+"/"+action, "archive-"+action, body), 409)
			}
		})
	}
}
