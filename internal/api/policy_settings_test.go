//go:build integration

package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"testing"
)

func TestOperationalSettings(t *testing.T) {
	f := newReviewFixtureDomain(t, "POLICY_API")
	var original []byte
	if err := f.owner.QueryRow(f.ctx, `SELECT value FROM cheesetrap.settings WHERE key='review_policy'`).Scan(&original); err != nil {
		t.Fatal(err)
	}
	defer f.owner.Exec(f.ctx, `UPDATE cheesetrap.settings SET value=$1 WHERE key='review_policy'`, original)
	// Old stored documents omit both keys; GET supplies the established values.
	if _, err := f.owner.Exec(f.ctx, `UPDATE cheesetrap.settings SET value=value-'delivery_limits'-'retention' WHERE key='review_policy'`); err != nil {
		t.Fatal(err)
	}
	before := decodeReview(t, f.get("/api/v1/settings"), 200)
	if before["retention"].(map[string]any)["event_days"] != float64(30) {
		t.Fatal(before)
	}

	// A pre-upgrade idempotency record has no new policy fields in its response.
	// Replaying it must preserve the successful historical response and defaults.
	var legacy settingsPatchInput
	period := 7
	legacy.Body.ExpectedVersion = before["version"].(string)
	legacy.Body.PeriodDays = &period
	encoded, _ := json.Marshal(struct {
		Method, Resource string
		Input            any
	}{"PATCH", "/api/v1/settings", legacy.Body})
	hash := sha256.Sum256(encoded)
	response := []byte(`{"version":"1","reply_to":"","timezone":"UTC","period_days":7,"schedule_version":"1","rule_effective_from_seq":"1","rules":{"ssh_repeat_threshold":10,"web_repeat_threshold":20,"web_distinct_path_threshold":5}}`)
	if _, err := f.owner.Exec(f.ctx, `INSERT INTO cheesetrap.review_idempotency(admin_id,key,request_hash,status,response) SELECT admin_id,'legacy-policy-response',$1,200,$2 FROM cheesetrap.admins WHERE username='admin'`, hex.EncodeToString(hash[:]), response); err != nil {
		t.Fatal(err)
	}
	old := decodeReview(t, f.mutate("PATCH", "/api/v1/settings", "legacy-policy-response", map[string]any{"expected_version": before["version"], "period_days": 7}), 200)
	if old["retention"].(map[string]any)["raw_bytes"] != "1073741824" {
		t.Fatal("legacy replay", old)
	}
	body := map[string]any{"expected_version": before["version"], "retention": map[string]any{"raw_days": 2, "raw_bytes": "33554432", "event_days": 60, "history_days": 360, "job_days": 3}}
	changed := decodeReview(t, f.mutate("PATCH", "/api/v1/settings", "operational-policy", body), 200)
	replay := decodeReview(t, f.mutate("PATCH", "/api/v1/settings", "operational-policy", body), 200)
	if !reflect.DeepEqual(changed, replay) || changed["version"] == before["version"] {
		t.Fatal("idempotency/version")
	}
	got := decodeReview(t, f.get("/api/v1/settings"), 200)
	if !reflect.DeepEqual(got["retention"], body["retention"]) {
		// JSON round trips integers as float64; compare the actual expected fields.
		if got["retention"].(map[string]any)["history_days"] != float64(360) {
			t.Fatal(got)
		}
	}
	body["expected_version"] = before["version"]
	decodeReview(t, f.mutate("PATCH", "/api/v1/settings", "operational-stale", body), 409)
	invalid := map[string]any{"expected_version": changed["version"], "retention": map[string]any{"event_days": 0}}
	decodeReview(t, f.mutate("PATCH", "/api/v1/settings", "operational-invalid", invalid), 422)
}
