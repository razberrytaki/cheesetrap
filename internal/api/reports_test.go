//go:build integration

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"cheesetrap/internal/auth"
	"cheesetrap/internal/detection"
	"cheesetrap/internal/domain"
	"cheesetrap/internal/enrichment"
	"cheesetrap/internal/jobs"
	"cheesetrap/internal/reporting"
	"cheesetrap/internal/store"
	"github.com/jackc/pgx/v5/pgxpool"
)

type reviewFixture struct {
	t                  *testing.T
	ctx                context.Context
	owner, api, worker *pgxpool.Pool
	h                  http.Handler
	token              string
	cookies            []*http.Cookie
	window             string
}

func newReviewFixture(t *testing.T) *reviewFixture {
	return newReviewFixtureDomain(t, "REVIEW")
}

func newReviewFixtureDomain(t *testing.T, domain string) *reviewFixture {
	t.Helper()
	f := &reviewFixture{t: t, ctx: context.Background()}
	for role, target := range map[string]**pgxpool.Pool{"MIGRATION": &f.owner, "API": &f.api, "WORKER": &f.worker} {
		p, err := store.NewPool(f.ctx, os.Getenv("CHEESETRAP_TEST_"+domain+"_"+role+"_URL"))
		if err != nil {
			t.Fatal(err)
		}
		*target = p
		t.Cleanup(p.Close)
	}
	var exists bool
	if err := f.owner.QueryRow(f.ctx, `SELECT EXISTS(SELECT 1 FROM cheesetrap.admins)`).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if !exists {
		if err := auth.NewService(f.api).CreateAdmin(f.ctx, "admin", "correct horse battery staple"); err != nil {
			t.Fatal(err)
		}
	}
	f.h = NewHandler(f.api, testOrigin)
	f.token, f.cookies = login(t, f.h)
	if err := f.owner.QueryRow(f.ctx, `INSERT INTO cheesetrap.report_windows(start_at,end_at,settings_version,state,sealed_seq,sealed_at,ready_at) VALUES(clock_timestamp()-interval '2 hours',clock_timestamp()-interval '1 hour',1,'ready',0,clock_timestamp(),clock_timestamp()) RETURNING window_id`).Scan(&f.window); err != nil {
		t.Fatal(err)
	}
	return f
}
func (f *reviewFixture) report(ip string, age ...time.Duration) (string, string) {
	f.t.Helper()
	now := time.Now().UTC().Add(-time.Minute)
	if len(age) > 0 {
		now = time.Now().UTC().Add(-age[0])
	}
	contact := enrichment.Result{SchemaVersion: 1, Address: ip, LookupSucceeded: true, QueriedAt: now, ExpiresAt: now.Add(time.Hour), HeldReason: "contact_ambiguous"}
	for _, email := range []string{"abuse@example.net", "security@example.net"} {
		contact.Candidates = append(contact.Candidates, enrichment.Contact{Email: email, Role: "abuse", Sources: []enrichment.Source{{Role: "abuse", Method: "rdap", SourceURL: "https://rdap.apnic.net/ip/1.1.1.1", NetworkStart: ip, NetworkEnd: ip}}})
	}
	registry, _ := json.Marshal(contact)
	var id string
	if err := f.owner.QueryRow(f.ctx, `INSERT INTO cheesetrap.reports(window_id,source_ip) VALUES($1,$2) RETURNING report_id`, f.window, ip).Scan(&id); err != nil {
		f.t.Fatal(err)
	}
	r := domain.ReportRevision{ReportID: id, Version: 1, State: "held", HoldReasons: []string{"contact_ambiguous", "reply_to_missing"}, Snapshot: domain.ReportSnapshot{SourceIP: ip, WindowID: f.window, WindowStart: now.Add(-time.Hour), WindowEnd: now, ObservedStart: now, ObservedEnd: now, Registry: registry, Rules: []domain.ReportRule{}, Evidence: []domain.ReportEvidence{}}}
	for i := range 3 {
		r.Snapshot.Evidence = append(r.Snapshot.Evidence, domain.ReportEvidence{EventID: fmt.Sprintf("30000000-0000-4000-8000-%012d", i+1), IngestionSeq: 9223372036854775804 + int64(i), ObservedAt: now, IngestedAt: now, SourceIP: ip, DestinationIP: "8.8.8.8", DestinationPort: 2222, Service: "ssh", QualityFlags: []string{}})
	}
	for i := range 3 {
		r.Snapshot.Rules = append(r.Snapshot.Rules, domain.ReportRule{DetectionID: fmt.Sprintf("50000000-0000-4000-8000-%012d", i+1), RuleID: "SSH-REPEAT", RuleVersion: "1", SettingsVersion: "1", ContextCount: 10, AttachedCount: 3, EvidenceEligible: true, AutoApprovalAllowed: i < 2, Explanation: json.RawMessage(`{"rule_version":"1","threshold":10,"count":10}`)})
	}
	r.Subject, r.Body, _ = reporting.Render(r)
	r.ContentDigest, _ = reporting.ContentDigest(r)
	snapshot, _ := json.Marshal(r.Snapshot)
	tx, err := f.owner.Begin(f.ctx)
	if err != nil {
		f.t.Fatal(err)
	}
	defer tx.Rollback(f.ctx)
	var rev string
	if err = tx.QueryRow(f.ctx, `INSERT INTO cheesetrap.report_revisions(report_id,version,snapshot,subject,body,recipient,reply_to,hold_reasons,state,auto_approval_allowed,body_edited,content_digest) VALUES($1,1,$2,$3,$4,'','',$5,'held',false,false,$6) RETURNING revision_id`, id, snapshot, r.Subject, r.Body, r.HoldReasons, r.ContentDigest).Scan(&rev); err != nil {
		f.t.Fatal(err)
	}
	if _, err = tx.Exec(f.ctx, `UPDATE cheesetrap.reports SET version=1,current_revision_id=$2,state='held' WHERE report_id=$1`, id, rev); err != nil {
		f.t.Fatal(err)
	}
	if err = tx.Commit(f.ctx); err != nil {
		f.t.Fatal(err)
	}
	return id, rev
}
func (f *reviewFixture) get(path string) *httptest.ResponseRecorder {
	return request(f.h, "GET", path, "", nil, f.cookies...)
}
func (f *reviewFixture) mutate(method, path, key string, body any) *httptest.ResponseRecorder {
	data, _ := json.Marshal(body)
	return request(f.h, method, path, string(data), map[string]string{"Origin": testOrigin, "X-CSRF-Token": f.token, "Content-Type": "application/json", "Idempotency-Key": key}, f.cookies...)
}
func decodeReview(t *testing.T, w *httptest.ResponseRecorder, want int) map[string]any {
	t.Helper()
	if w.Code != want {
		t.Fatalf("status=%d want=%d body=%s", w.Code, want, w.Body.String())
	}
	var b map[string]any
	if json.Unmarshal(w.Body.Bytes(), &b) != nil {
		t.Fatal("invalid JSON")
	}
	return b
}
func TestReviewAPI(t *testing.T) {
	f := newReviewFixture(t)
	id, rev := f.report("1.1.1.1")
	id2, _ := f.report("9.9.9.9")
	t.Run("bounded_reads_and_security", func(t *testing.T) {
		if w := request(f.h, "GET", "/api/v1/reports", "", nil); w.Code != 401 {
			t.Fatalf("unauthenticated reports status=%d want401", w.Code)
		}
		page := decodeReview(t, f.get("/api/v1/reports?limit=1"), 200)
		if len(page["items"].([]any)) != 1 || page["next_cursor"] == "" {
			t.Fatal("missing pagination")
		}
		next := decodeReview(t, f.get("/api/v1/reports?limit=1&cursor="+page["next_cursor"].(string)), 200)
		if len(next["items"].([]any)) != 1 || next["next_cursor"] != "" {
			t.Fatal("unstable report pagination")
		}
		detail := decodeReview(t, f.get("/api/v1/reports/"+id), 200)
		if detail["version"] != "1" || detail["current_revision_id"] != rev {
			t.Fatal("missing version contract")
		}
		if strings.Contains(f.get("/api/v1/reports/"+id).Body.String(), `"ingestion_seq"`) {
			t.Fatal("detail exposed unbounded evidence")
		}
		evidence := decodeReview(t, f.get("/api/v1/reports/"+id+"/revisions/"+rev+"/evidence?limit=2"), 200)
		if len(evidence["items"].([]any)) != 2 || evidence["next_cursor"] == "" || evidence["items"].([]any)[0].(map[string]any)["ingestion_seq"] != "9223372036854775804" {
			t.Fatal("unbounded or lossy evidence")
		}
		rules := decodeReview(t, f.get("/api/v1/reports/"+id+"/revisions/"+rev+"/rules?limit=2"), 200)
		if len(rules["items"].([]any)) != 2 || rules["next_cursor"] == "" || rules["items"].([]any)[0].(map[string]any)["settings_version"] != "1" {
			t.Fatal("rules pagination/provenance missing")
		}
		second := decodeReview(t, f.get("/api/v1/reports/"+id+"/revisions/"+rev+"/rules?limit=2&cursor="+rules["next_cursor"].(string)), 200)
		if len(second["items"].([]any)) != 1 || second["next_cursor"] != "" {
			t.Fatal("rules cursor skipped entries")
		}
		decodeReview(t, f.get("/api/v1/ips/1.1.1.1?limit=1"), 200)
		if w := f.get("/api/v1/ips/127.0.0.1"); w.Code != 400 {
			t.Fatalf("unsafe address accepted status=%d", w.Code)
		}
		if w := request(f.h, "POST", "/api/v1/reports/"+id+"/reject", `{}`, map[string]string{"Origin": testOrigin, "Content-Type": "application/json"}, f.cookies...); w.Code != 403 {
			t.Fatal("CSRF bypass")
		}
	})
	t.Run("optimistic_revision_idempotency_and_terminal_reject", func(t *testing.T) {
		path := "/api/v1/reports/" + id + "/select-contact"
		body := map[string]any{"expected_version": "1", "current_revision_id": rev, "recipient": "abuse@example.net"}
		bad := map[string]any{"expected_version": "1", "current_revision_id": "00000000-0000-4000-8000-000000000000", "recipient": "abuse@example.net"}
		decodeReview(t, f.mutate("POST", path, "wrong-revision", bad), 409)
		var wg sync.WaitGroup
		responses := make([]*httptest.ResponseRecorder, 4)
		for i := range responses {
			wg.Add(1)
			go func() { defer wg.Done(); responses[i] = f.mutate("POST", path, "select-once", body) }()
		}
		wg.Wait()
		result := decodeReview(t, responses[0], 200)
		for _, w := range responses[1:] {
			decodeReview(t, w, 200)
			if w.Body.String() != responses[0].Body.String() {
				t.Fatal("idempotent response changed")
			}
		}
		selectedDetail := decodeReview(t, f.get("/api/v1/reports/"+id), 200)
		if _, present := selectedDetail["revision"].(map[string]any)["auto_approval_allowed"]; present {
			t.Fatal("selection removed signature gate")
		}
		if result["version"] != "2" || result["current_revision_id"] == rev {
			t.Fatal("selection did not append immutable revision")
		}
		// The edited legacy revision now signs sealed parts. Every paginated
		// record and total must remain identical to the historical inline view.
		for _, kind := range []string{"evidence", "rules"} {
			oldPage := decodeReview(t, f.get("/api/v1/reports/"+id+"/revisions/"+rev+"/"+kind+"?limit=2"), 200)
			newPage := decodeReview(t, f.get("/api/v1/reports/"+id+"/revisions/"+result["current_revision_id"].(string)+"/"+kind+"?limit=2"), 200)
			oldItems, _ := json.Marshal(oldPage["items"])
			newItems, _ := json.Marshal(newPage["items"])
			if string(oldItems) != string(newItems) || oldPage["total"] != newPage["total"] {
				t.Fatal("proof pagination changed copies", kind)
			}
		}
		decodeReview(t, f.mutate("POST", path, "stale-select", body), 409)
		body["recipient"] = "security@example.net"
		decodeReview(t, f.mutate("POST", path, "select-once", body), 409)
		history := decodeReview(t, f.get("/api/v1/reports/"+id+"/revisions?limit=1"), 200)
		if history["next_cursor"] == "" {
			t.Fatal("history not paginated")
		}
		old := decodeReview(t, f.get("/api/v1/reports/"+id+"/revisions/"+rev), 200)
		if old["recipient"] != "" {
			t.Fatal("old revision mutated")
		}
		current := map[string]any{"expected_version": "2", "current_revision_id": result["current_revision_id"]}
		rejected := decodeReview(t, f.mutate("POST", "/api/v1/reports/"+id+"/reject", "reject-once", current), 200)
		if rejected["state"] != "rejected" || rejected["version"] != "3" {
			t.Fatal("rejection missing")
		}
		current["expected_version"] = "3"
		current["recipient"] = "abuse@example.net"
		decodeReview(t, f.mutate("POST", path, "revive", current), 409)
		decodeReview(t, f.mutate("POST", "/api/v1/reports/"+id+"/refresh-contact", "refresh-rejected", map[string]any{"expected_version": "3", "current_revision_id": result["current_revision_id"]}), 409)
		var count int
		if err := f.owner.QueryRow(f.ctx, `SELECT count(*) FROM cheesetrap.audit WHERE action='report_contact_selected' AND details->>'report_id'=$1`, id).Scan(&count); err != nil || count != 1 {
			t.Fatalf("duplicate audit count=%d err=%v", count, err)
		}
	})
	t.Run("settings_version_and_validation", func(t *testing.T) {
		if _, err := f.owner.Exec(f.ctx, `INSERT INTO cheesetrap.sensors(sensor_id,name,engine) VALUES('10000000-0000-4000-8000-000000000506','review-rules','cowrie'); INSERT INTO cheesetrap.file_generations(file_generation_id,sensor_id,path,device,inode) VALUES('20000000-0000-4000-8000-000000000506','10000000-0000-4000-8000-000000000506','/fixture',1,1);
   INSERT INTO cheesetrap.events(sensor_id,file_generation_id,byte_offset,ingestion_seq,schema_version,engine,observed_at,source_ip,destination_ip,destination_port,service,event_type,raw_hash) SELECT '10000000-0000-4000-8000-000000000506','20000000-0000-4000-8000-000000000506',n,n,1,'cowrie',clock_timestamp(),'4.2.2.1','8.8.8.8',22,'ssh','cowrie.login.failed',repeat('a',64) FROM generate_series(1,2)n;UPDATE cheesetrap.processing_cursors SET ingested_seq=2`); err != nil {
			t.Fatal(err)
		}
		b := decodeReview(t, f.get("/api/v1/settings"), 200)
		patch := map[string]any{"expected_version": b["version"], "reply_to": "operator@example.org", "timezone": "Asia/Tokyo", "period_days": 2, "rules": map[string]any{"ssh_repeat_threshold": 2, "web_repeat_threshold": 3, "web_distinct_path_threshold": 2}}
		w := f.mutate("PATCH", "/api/v1/settings", "settings-once", patch)
		result := decodeReview(t, w, 200)
		if result["rule_effective_from_seq"] != "3" {
			t.Fatal("settings did not respect ingestion boundary", result)
		}
		if result["version"] == b["version"] {
			t.Fatal("settings version unchanged")
		}
		replay := f.mutate("PATCH", "/api/v1/settings", "settings-once", patch)
		decodeReview(t, replay, 200)
		if replay.Body.String() != w.Body.String() {
			t.Fatal("settings replay changed")
		}
		decodeReview(t, f.mutate("PATCH", "/api/v1/settings", "settings-stale", patch), 409)
		patch["expected_version"] = result["version"]
		patch["rules"] = map[string]any{"ssh_repeat_threshold": 1, "web_repeat_threshold": 3, "web_distinct_path_threshold": 2}
		invalid := f.mutate("PATCH", "/api/v1/settings", "settings-invalid", patch)
		if invalid.Code != 400 && invalid.Code != 422 {
			t.Fatal("single login threshold accepted")
		}
		patch["rules"] = map[string]any{"ssh_repeat_threshold": 4, "web_repeat_threshold": 3, "web_distinct_path_threshold": 2}
		latest := decodeReview(t, f.mutate("PATCH", "/api/v1/settings", "same-boundary-latest", patch), 200)
		if latest["rule_effective_from_seq"] != "3" {
			t.Fatal("same boundary moved")
		}
		appendEvent := func(n int) {
			t.Helper()
			if _, err := f.owner.Exec(f.ctx, `INSERT INTO cheesetrap.events(sensor_id,file_generation_id,byte_offset,ingestion_seq,schema_version,engine,observed_at,source_ip,destination_ip,destination_port,service,event_type,raw_hash) VALUES('10000000-0000-4000-8000-000000000506','20000000-0000-4000-8000-000000000506',$1,$1,1,'cowrie',clock_timestamp(),'4.2.2.1','8.8.8.8',22,'ssh','cowrie.login.failed',repeat('a',64))`, n); err != nil {
				t.Fatal(err)
			}
			if _, err := f.owner.Exec(f.ctx, `UPDATE cheesetrap.processing_cursors SET ingested_seq=$1`, n); err != nil {
				t.Fatal(err)
			}
		}
		appendEvent(3)
		if _, err := detection.ProcessBatch(f.ctx, f.worker, 100); err != nil {
			t.Fatal(err)
		}
		var count int
		if err := f.owner.QueryRow(f.ctx, `SELECT count(*) FROM cheesetrap.detection_results WHERE source_ip='4.2.2.1'`).Scan(&count); err != nil || count != 0 {
			t.Fatal("superseded same-boundary config used", count, err)
		}
		var versions []string
		if err := f.owner.QueryRow(f.ctx, `SELECT array_agg(settings_version::text ORDER BY ingestion_seq) FROM cheesetrap.detection_completions`).Scan(&versions); err != nil || len(versions) != 3 || versions[0] != "1" || versions[1] != "1" || versions[2] != latest["version"] {
			t.Fatal("PATCH rerated prior ingestion backlog", versions, err)
		}
		appendEvent(4)
		if _, err := detection.ProcessBatch(f.ctx, f.worker, 100); err != nil {
			t.Fatal(err)
		}
		ip := decodeReview(t, f.get("/api/v1/ips/4.2.2.1?detection_limit=1"), 200)
		judgments := ip["detections"].([]any)
		if len(judgments) != 1 || judgments[0].(map[string]any)["settings_version"] != latest["version"] || judgments[0].(map[string]any)["processing_ingestion_seq"] != "4" {
			t.Fatal("PATCH threshold did not drive real processor", ip)
		}

		// Owner-only fixture simulates the Task 3 retiring state.
		if _, err := f.owner.Exec(f.ctx, `BEGIN; ALTER TABLE cheesetrap.detection_results DISABLE TRIGGER guard_evidence_root; UPDATE cheesetrap.detection_results SET evidence_state='retiring' WHERE source_ip='4.2.2.1'; ALTER TABLE cheesetrap.detection_results ENABLE TRIGGER guard_evidence_root; COMMIT`); err != nil {
			t.Fatal(err)
		}
		hidden := decodeReview(t, f.get("/api/v1/ips/4.2.2.1?detection_limit=1"), 200)
		if len(hidden["detections"].([]any)) != 0 {
			t.Fatal("retiring detection exposed by IP API")
		}
	})
	t.Run("refresh_atomic_queue_repair_and_worker", func(t *testing.T) {
		var original string
		if err := f.owner.QueryRow(f.ctx, `SELECT current_revision_id::text FROM cheesetrap.reports WHERE report_id=$1`, id2).Scan(&original); err != nil {
			t.Fatal(err)
		}
		body := map[string]any{"expected_version": "1", "current_revision_id": original}
		first := f.mutate("POST", "/api/v1/reports/"+id2+"/refresh-contact", "refresh-once", body)
		queued := decodeReview(t, first, 202)
		if queued["version"] != "2" || queued["current_revision_id"] != original || queued["refresh_request_id"] == "" {
			t.Fatal("refresh did not preserve content pointer")
		}
		replay := f.mutate("POST", "/api/v1/reports/"+id2+"/refresh-contact", "refresh-once", body)
		decodeReview(t, replay, 202)
		if first.Body.String() != replay.Body.String() {
			t.Fatal("refresh replay changed")
		}
		requestID := queued["refresh_request_id"].(string)
		var n int
		if err := f.owner.QueryRow(f.ctx, `SELECT count(*) FROM cheesetrap_river.river_job WHERE kind='refresh_contact' AND args->>'request_id'=$1`, requestID).Scan(&n); err != nil || n != 1 {
			t.Fatalf("duplicate/missing refresh job count=%d err=%v", n, err)
		}
		if _, err := f.owner.Exec(f.ctx, `UPDATE cheesetrap_river.river_job SET state='discarded',finalized_at=clock_timestamp() WHERE kind='refresh_contact' AND args->>'request_id'=$1`, requestID); err != nil {
			t.Fatal(err)
		}
		client, err := jobs.NewClient(f.worker)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = jobs.Reconcile(f.ctx, f.worker, client); err != nil {
			t.Fatal(err)
		}
		if err = f.owner.QueryRow(f.ctx, `SELECT count(*) FROM cheesetrap_river.river_job WHERE kind='refresh_contact' AND args->>'request_id'=$1 AND state='available'`, requestID).Scan(&n); err != nil || n != 1 {
			t.Fatal("discarded refresh was not repaired", err, n)
		}
		// Persisted synthetic registry evidence is newer than the request. The real
		// worker consumes it without issuing any external registry request.
		var registry enrichment.Result
		var data []byte
		if err = f.owner.QueryRow(f.ctx, `SELECT snapshot->'registry' FROM cheesetrap.report_revisions WHERE revision_id=$1`, original).Scan(&data); err != nil {
			t.Fatal(err)
		}
		if json.Unmarshal(data, &registry) != nil {
			t.Fatal("registry fixture invalid")
		}
		registry.QueriedAt = time.Now().UTC()
		registry.ExpiresAt = registry.QueriedAt.Add(time.Hour)
		registry.Candidates = registry.Candidates[:1]
		registry.Candidates[0].Email = "fresh@example.net"
		registry.HeldReason = ""
		data, _ = json.Marshal(registry)
		if _, err = f.owner.Exec(f.ctx, `INSERT INTO cheesetrap.enrichment_cache(address,result,queried_at,expires_at) VALUES('9.9.9.9',$1,$2,$3)`, data, registry.QueriedAt, registry.ExpiresAt); err != nil {
			t.Fatal(err)
		}
		if err = client.Start(f.ctx); err != nil {
			t.Fatal(err)
		}
		defer client.StopAndCancel(f.ctx)
		deadline := time.Now().Add(8 * time.Second)
		for {
			var status string
			if err = f.owner.QueryRow(f.ctx, `SELECT status FROM cheesetrap.contact_refresh_requests WHERE request_id=$1`, requestID).Scan(&status); err != nil {
				t.Fatal(err)
			}
			if status == "completed" {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("worker did not complete queued refresh")
			}
			time.Sleep(25 * time.Millisecond)
		}
		detail := decodeReview(t, f.get("/api/v1/reports/"+id2), 200)
		if detail["version"] != "3" || detail["current_revision_id"] == original || detail["revision"].(map[string]any)["recipient"] != "fresh@example.net" {
			t.Fatal("fresh registry did not create revision", detail)
		}
		decodeReview(t, f.mutate("POST", "/api/v1/reports/"+id2+"/refresh-contact", "refresh-once", body), 202)
	})
	t.Run("expired_contact_selection_denied", func(t *testing.T) {
		report, revision := f.report("8.8.4.4", 2*time.Hour)
		decodeReview(t, f.mutate("POST", "/api/v1/reports/"+report+"/select-contact", "expired-select", map[string]any{"expected_version": "1", "current_revision_id": revision, "recipient": "abuse@example.net"}), 400)
		detail := decodeReview(t, f.get("/api/v1/reports/"+report), 200)
		if detail["version"] != "1" {
			t.Fatal("expired selection mutated revision")
		}
	})
	t.Run("settings_audit_failure_rolls_back_versions", func(t *testing.T) {
		original := decodeReview(t, f.get("/api/v1/settings"), 200)
		var rules, schedules int
		if err := f.owner.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM cheesetrap.rule_config_versions),(SELECT count(*) FROM cheesetrap.reporting_schedule_versions)`).Scan(&rules, &schedules); err != nil {
			t.Fatal(err)
		}
		if _, err := f.owner.Exec(f.ctx, `REVOKE INSERT ON cheesetrap.audit FROM cheesetrap_api`); err != nil {
			t.Fatal(err)
		}
		response := f.mutate("PATCH", "/api/v1/settings", "settings-failed-audit", map[string]any{"expected_version": original["version"], "timezone": "Europe/London", "reply_to": "rollback@example.org"})
		if _, err := f.owner.Exec(f.ctx, `GRANT INSERT ON cheesetrap.audit TO cheesetrap_api`); err != nil {
			t.Fatal(err)
		}
		decodeReview(t, response, 503)
		after := decodeReview(t, f.get("/api/v1/settings"), 200)
		if after["version"] != original["version"] || after["reply_to"] != original["reply_to"] || after["timezone"] != original["timezone"] {
			t.Fatal("failed settings patch leaked values")
		}
		var nextRules, nextSchedules, keys int
		if err := f.owner.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM cheesetrap.rule_config_versions),(SELECT count(*) FROM cheesetrap.reporting_schedule_versions),(SELECT count(*) FROM cheesetrap.review_idempotency WHERE key='settings-failed-audit')`).Scan(&nextRules, &nextSchedules, &keys); err != nil || nextRules != rules || nextSchedules != schedules || keys != 0 {
			t.Fatal("failed settings patch leaked histories", err)
		}
	})
	t.Run("audit_and_job_failures_rollback_entire_command", func(t *testing.T) {
		for i, table := range []string{"cheesetrap.audit", "cheesetrap_river.river_job"} {
			id, rev := f.report(fmt.Sprintf("8.8.8.%d", i+1))
			key := fmt.Sprintf("failed-refresh-%d", i)
			if _, err := f.owner.Exec(f.ctx, "REVOKE INSERT ON "+table+" FROM cheesetrap_api"); err != nil {
				t.Fatal(err)
			}
			w := f.mutate("POST", "/api/v1/reports/"+id+"/refresh-contact", key, map[string]any{"expected_version": "1", "current_revision_id": rev})
			if _, err := f.owner.Exec(f.ctx, "GRANT INSERT ON "+table+" TO cheesetrap_api"); err != nil {
				t.Fatal(err)
			}
			decodeReview(t, w, 503)
			var version int64
			var requests, idem int
			if err := f.owner.QueryRow(f.ctx, `SELECT version,(SELECT count(*) FROM cheesetrap.contact_refresh_requests WHERE report_id=$1),(SELECT count(*) FROM cheesetrap.review_idempotency WHERE key=$2) FROM cheesetrap.reports WHERE report_id=$1`, id, key).Scan(&version, &requests, &idem); err != nil || version != 1 || requests != 0 || idem != 0 {
				t.Fatalf("failed transaction leaked state %d %d %d %v", version, requests, idem, err)
			}
		}
	})
}

// A lease prevents all external I/O while a real worker is running. Publishing
// newer synthetic evidence releases it only after the competing review command.
func TestReviewAPIRefreshFencing(t *testing.T) {
	f := newReviewFixture(t)
	client, err := jobs.NewClient(f.worker)
	if err != nil {
		t.Fatal(err)
	}
	if err = client.Start(f.ctx); err != nil {
		t.Fatal(err)
	}
	defer client.StopAndCancel(f.ctx)
	for i, action := range []string{"select", "reject", "newer_refresh", "settings"} {
		t.Run(action, func(t *testing.T) {
			ip := fmt.Sprintf("1.0.0.%d", i+1)
			id, rev := f.report(ip)
			var data []byte
			if err := f.owner.QueryRow(f.ctx, `SELECT snapshot->'registry' FROM cheesetrap.report_revisions WHERE revision_id=$1`, rev).Scan(&data); err != nil {
				t.Fatal(err)
			}
			var registry enrichment.Result
			if json.Unmarshal(data, &registry) != nil {
				t.Fatal("registry invalid")
			}
			if _, err := f.owner.Exec(f.ctx, `INSERT INTO cheesetrap.enrichment_cache(address,result,queried_at,expires_at,lease_token,lease_expires_at) VALUES($1,$2,$3,$4,gen_random_uuid(),clock_timestamp()+interval '2 minutes')`, ip, data, registry.QueriedAt, registry.ExpiresAt); err != nil {
				t.Fatal(err)
			}
			body := map[string]any{"expected_version": "1", "current_revision_id": rev}
			queued := decodeReview(t, f.mutate("POST", "/api/v1/reports/"+id+"/refresh-contact", "fence-"+action, body), 202)
			first := queued["refresh_request_id"].(string)
			deadline := time.Now().Add(6 * time.Second)
			for {
				var running bool
				if err := f.owner.QueryRow(f.ctx, `SELECT EXISTS(SELECT 1 FROM cheesetrap_river.river_job WHERE kind='refresh_contact' AND args->>'request_id'=$1 AND state='running')`, first).Scan(&running); err != nil {
					t.Fatal(err)
				}
				if running {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("worker never started")
				}
				time.Sleep(10 * time.Millisecond)
			}
			body["expected_version"] = "2"
			expectedVersion := "3"
			expectedRevision := rev
			second := ""
			switch action {
			case "select":
				body["recipient"] = "security@example.net"
				selected := decodeReview(t, f.mutate("POST", "/api/v1/reports/"+id+"/select-contact", "select-while-refresh", body), 200)
				expectedRevision = selected["current_revision_id"].(string)
			case "reject":
				decodeReview(t, f.mutate("POST", "/api/v1/reports/"+id+"/reject", "reject-while-refresh", body), 200)
			case "newer_refresh":
				newer := decodeReview(t, f.mutate("POST", "/api/v1/reports/"+id+"/refresh-contact", "newer-refresh", body), 202)
				second = newer["refresh_request_id"].(string)
				expectedVersion = "4"
			case "settings":
				settings := decodeReview(t, f.get("/api/v1/settings"), 200)
				decodeReview(t, f.mutate("PATCH", "/api/v1/settings", "settings-while-refresh", map[string]any{"expected_version": settings["version"], "reply_to": "new@example.org"}), 200)
				expectedVersion = "2"
			}
			if err := f.owner.QueryRow(f.ctx, `SELECT clock_timestamp()`).Scan(&registry.QueriedAt); err != nil {
				t.Fatal(err)
			}
			registry.ExpiresAt = registry.QueriedAt.Add(time.Hour)
			registry.Candidates = registry.Candidates[:1]
			registry.Candidates[0].Email = "fresh@example.net"
			registry.HeldReason = ""
			data, _ = json.Marshal(registry)
			if _, err := f.owner.Exec(f.ctx, `UPDATE cheesetrap.enrichment_cache SET result=$2,queried_at=$3,expires_at=$4,lease_token=NULL,lease_expires_at=NULL WHERE address=$1`, ip, data, registry.QueriedAt, registry.ExpiresAt); err != nil {
				t.Fatal(err)
			}
			deadline = time.Now().Add(6 * time.Second)
			for {
				var done bool
				if err := f.owner.QueryRow(f.ctx, `SELECT NOT EXISTS(SELECT 1 FROM cheesetrap_river.river_job WHERE kind='refresh_contact' AND args->>'request_id'=ANY($1::text[]) AND state NOT IN ('completed','cancelled','discarded'))`, []string{first, second}).Scan(&done); err != nil {
					t.Fatal(err)
				}
				if done {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("worker did not finish fenced lookup")
				}
				time.Sleep(10 * time.Millisecond)
			}
			detail := decodeReview(t, f.get("/api/v1/reports/"+id), 200)
			if detail["version"] != expectedVersion {
				t.Fatal("stale worker changed aggregate", detail)
			}
			if second == "" && detail["current_revision_id"] != expectedRevision {
				t.Fatal("stale worker overwrote selected revision", detail)
			}
			var status string
			if err := f.owner.QueryRow(f.ctx, `SELECT status FROM cheesetrap.contact_refresh_requests WHERE request_id=$1`, first).Scan(&status); err != nil || status != "superseded" {
				t.Fatal("old request not terminal", status, err)
			}
			if action == "reject" && detail["state"] != "rejected" {
				t.Fatal("rejected report revived")
			}
			if action == "newer_refresh" && (detail["current_revision_id"] == rev || detail["latest_refresh"].(map[string]any)["status"] != "completed") {
				t.Fatal("latest request lost")
			}
		})
	}
}

// The authenticated edit may scan a large proof for longer than the ordinary
// API budget. Exercise both context and HTTP write deadlines on a real socket.
func TestProofCommandBudget(t *testing.T) {
	f := newReviewFixture(t)
	id, revision := f.report("1.0.0.1")
	_, err := f.owner.Exec(f.ctx, `CREATE FUNCTION cheesetrap.test_slow_revision() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(11); RETURN NEW; END $$; CREATE TRIGGER test_slow_revision BEFORE INSERT ON cheesetrap.report_revisions FOR EACH ROW EXECUTE FUNCTION cheesetrap.test_slow_revision()`)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = f.owner.Exec(context.Background(), `DROP TRIGGER test_slow_revision ON cheesetrap.report_revisions; DROP FUNCTION cheesetrap.test_slow_revision()`)
	})
	ts := httptest.NewUnstartedServer(f.h)
	ts.Config.WriteTimeout = time.Second
	ts.Start()
	defer ts.Close()
	body, _ := json.Marshal(map[string]any{"expected_version": "1", "current_revision_id": revision, "recipient": "abuse@example.net"})
	req, _ := http.NewRequest("POST", ts.URL+"/api/v1/reports/"+id+"/select-contact", strings.NewReader(string(body)))
	req.Host = "127.0.0.1:8080"
	req.Header.Set("Origin", testOrigin)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", f.token)
	req.Header.Set("Idempotency-Key", "proof-budget")
	for _, cookie := range f.cookies {
		req.AddCookie(cookie)
	}
	res, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatal("large-proof command deadline", res.StatusCode)
	}
	var version int
	if err := f.owner.QueryRow(f.ctx, `SELECT version FROM cheesetrap.reports WHERE report_id=$1`, id).Scan(&version); err != nil || version != 2 {
		t.Fatal("edit did not commit", version, err)
	}
}
