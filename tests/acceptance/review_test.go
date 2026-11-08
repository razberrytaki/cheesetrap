//go:build integration

package acceptance

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cheesetrap/internal/api"
	"cheesetrap/internal/auth"
	"cheesetrap/internal/detection"
	"cheesetrap/internal/enrichment"
	"cheesetrap/internal/ingestion"
	"cheesetrap/internal/reporting"
	"cheesetrap/internal/store"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestReviewFlow uses synthetic engine files, the real collector and parser,
// real detection and report services, and authenticated HTTP. Only registry
// I/O is replaced with a closed synthetic transport. No report rows are seeded.
func TestReviewFlow(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	pools := map[string]*pgxpool.Pool{}
	for _, role := range []string{"MIGRATION", "API", "WORKER"} {
		url := os.Getenv("CHEESETRAP_TEST_REVIEW_FLOW_" + role + "_URL")
		if url == "" {
			t.Fatal("isolated review-flow database required")
		}
		p, err := store.NewPool(ctx, url)
		if err != nil {
			t.Fatal("review-flow database unavailable")
		}
		defer p.Close()
		pools[role] = p
	}
	owner, worker := pools["MIGRATION"], pools["WORKER"]
	count := func(query string) int {
		t.Helper()
		var n int
		if err := owner.QueryRow(ctx, query).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	dir := t.TempDir()
	log := filepath.Join(dir, "cowrie.json")
	manifest := filepath.Join(t.TempDir(), "sources.json")
	source := ingestion.Source{SensorID: "10000000-0000-4000-8000-000000000707", Name: "review-fixture", Engine: "cowrie", Path: "cowrie.json", IsTest: true, Endpoints: []ingestion.Endpoint{{Service: "ssh", ObservedIP: "172.30.91.10", ObservedPort: 2222, PublicIP: "192.0.2.10", PublicPort: 2222}}}
	data, _ := json.Marshal([]ingestion.Source{source})
	if err := os.WriteFile(manifest, data, 0600); err != nil {
		t.Fatal(err)
	}
	observed := time.Now().UTC().Add(-time.Minute)
	fixture, err := os.ReadFile("../../testdata/engines/cowrie/events.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	originals := map[string]map[string]any{}
	for _, raw := range strings.Split(strings.TrimSpace(string(fixture)), "\n") {
		var record map[string]any
		if json.Unmarshal([]byte(raw), &record) != nil {
			t.Fatal("invalid engine fixture")
		}
		kind, _ := record["eventid"].(string)
		if originals[kind] == nil {
			originals[kind] = record
		}
	}
	line := func(event string, n int) string {
		record := map[string]any{}
		for k, v := range originals[event] {
			record[k] = v
		}
		if len(record) == 0 {
			t.Fatal("required captured Cowrie event missing")
		}
		record["timestamp"] = observed.Add(time.Duration(n) * time.Second).Format(time.RFC3339Nano)
		record["src_ip"] = "1.1.1.1"
		record["dst_ip"] = "172.30.91.10"
		b, _ := json.Marshal(record)
		return string(b) + "\n"
	}
	collect := func(text string, want int) {
		t.Helper()
		var checkpoint time.Time
		if err := owner.QueryRow(ctx, "SELECT coalesce(max(updated_at),'epoch'::timestamptz) FROM cheesetrap.checkpoints").Scan(&checkpoint); err != nil {
			t.Fatal(err)
		}
		f, err := os.OpenFile(log, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		_, err = f.WriteString(text)
		f.Close()
		if err != nil {
			t.Fatal(err)
		}
		cctx, stop := context.WithCancel(ctx)
		done := make(chan error, 1)
		go func() {
			done <- ingestion.RunCollector(cctx, os.Getenv("CHEESETRAP_TEST_REVIEW_FLOW_COLLECTOR_URL"), dir, manifest)
		}()
		defer func() {
			stop()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Error("collector did not stop")
			}
		}()
		deadline := time.Now().Add(10 * time.Second)
		for {
			select {
			case err := <-done:
				done <- err
				t.Fatal("collector exited before durable observation", err)
			default:
			}
			var newer time.Time
			if err := owner.QueryRow(ctx, "SELECT coalesce(max(updated_at),'epoch'::timestamptz) FROM cheesetrap.checkpoints").Scan(&newer); err != nil {
				t.Fatal(err)
			}
			if count("SELECT count(*) FROM cheesetrap.events") == want && newer.After(checkpoint) {
				break
			}
			if time.Now().After(deadline) {
				var used *float64
				var available bool
				if err := owner.QueryRow(ctx, "SELECT used_percent,available FROM cheesetrap.storage_status WHERE component='collector'").Scan(&used, &available); err != nil {
					t.Log("collector storage observation unavailable")
				} else if used != nil {
					t.Logf("collector storage: available=%t used_percent=%.2f restricted=%t", available, *used, !available || *used >= 90)
				} else {
					t.Logf("collector storage: available=%t used_percent=unknown", available)
				}
				t.Logf("fixture progress: events=%d want=%d checkpoint_advanced=%t", count("SELECT count(*) FROM cheesetrap.events"), want, newer.After(checkpoint))
				t.Fatal("collector failed to ingest fixture")
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	process := func() {
		t.Helper()
		if _, err := detection.ProcessBatch(ctx, worker, 1000); err != nil {
			t.Fatal(err)
		}
	}
	// A simple connection is retained without creating a detection or report.
	collect(line("cowrie.session.connect", 0), 1)
	process()
	if count("SELECT count(*) FROM cheesetrap.detection_results") != 0 {
		t.Fatal("simple connection became attack")
	}
	// Nine failures alone are below the default repeat threshold. Arrival order
	// deliberately reverses observation time; the last arrival completes the set.
	text := ""
	for n := 10; n >= 2; n-- {
		text += line("cowrie.login.failed", n)
	}
	collect(text, 10)
	var start time.Time
	if err := owner.QueryRow(ctx, "SELECT min(ingested_at)-interval '1 second' FROM cheesetrap.events").Scan(&start); err != nil {
		t.Fatal(err)
	}
	newWindow := func(start, end time.Time) string {
		t.Helper()
		var id string
		if err := owner.QueryRow(ctx, "INSERT INTO cheesetrap.report_windows(start_at,end_at,settings_version) VALUES($1,$2,1) RETURNING window_id", start, end).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	var end time.Time
	if err := owner.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&end); err != nil {
		t.Fatal(err)
	}
	first := newWindow(start, end)
	ready, err := reporting.SealWindow(ctx, worker, first)
	if err != nil || ready {
		t.Fatal("lagging detection finalized early", err)
	}
	registry := &enrichment.AcceptanceRegistry{}
	draft := reporting.NewAcceptanceDraftService(worker, registry)
	if progress, err := draft.Next(ctx); err != nil || progress.Processed {
		t.Fatal("draft bypassed detection barrier", err)
	}
	process()
	if count("SELECT count(*) FROM cheesetrap.detection_results") != 0 {
		t.Fatal("below threshold repeat detected")
	}
	if ready, err = reporting.SealWindow(ctx, worker, first); err != nil || !ready {
		t.Fatal("first window not ready", err)
	}
	if _, err = draft.Next(ctx); err != nil {
		t.Fatal(err)
	}
	if count("SELECT count(*) FROM cheesetrap.reports") != 0 {
		t.Fatal("below-threshold evidence produced report")
	}
	// Final late-ingested observation completes the reversed repeat in window 2.
	collect(line("cowrie.login.failed", 1), 11)
	process()
	var end2 time.Time
	owner.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&end2)
	second := newWindow(end, end2)
	if ready, err = reporting.SealWindow(ctx, worker, second); err != nil || !ready {
		t.Fatal("late window not ready", err)
	}
	if err = reporting.SetReplyTo(ctx, pools["API"], "operator@example.test"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		if _, err = draft.Next(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if count("SELECT count(*) FROM cheesetrap.reports") != 1 {
		t.Fatal("completed repeat did not yield exactly one report")
	}
	if registry.Calls != 2 {
		t.Fatalf("mock RDAP pipeline calls=%d want2", registry.Calls)
	}
	var reportID, original string
	if err = owner.QueryRow(ctx, "SELECT report_id,row_to_json(r)::text FROM cheesetrap.report_revisions r").Scan(&reportID, &original); err != nil {
		t.Fatal(err)
	}
	var storedRules string
	if err = owner.QueryRow(ctx, "SELECT string_agg(convert_from(payload,'UTF8'),'') FROM cheesetrap.report_proof_parts WHERE report_id=$1 AND kind='rules'", reportID).Scan(&storedRules); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(storedRules, "SSH-REPEAT") || !strings.Contains(original, "repeated failed SSH authentication attempts") || !strings.Contains(original, "contact_ambiguous") || strings.Contains(original, "secret-password") || strings.Contains(original, "m0-invalid-user") {
		t.Fatal("report lost rule/contact policy or leaked credentials")
	}
	if !strings.Contains(original, second) {
		t.Fatal("repeat belongs to late-ingestion window")
	}
	// Another match may reference older context, but only its one new event can
	// become new report evidence. The prior revision remains byte-for-byte frozen.
	collect(line("cowrie.login.failed", 11), 12)
	process()
	var end3 time.Time
	owner.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&end3)
	third := newWindow(end2, end3)
	if ready, err = reporting.SealWindow(ctx, worker, third); err != nil || !ready {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		if _, err = draft.Next(ctx); err != nil {
			t.Fatal(err)
		}
	}
	var after string
	if err = owner.QueryRow(ctx, "SELECT row_to_json(r)::text FROM cheesetrap.report_revisions r WHERE report_id=$1", reportID).Scan(&after); err != nil || after != original {
		t.Fatal("later ingestion mutated prior report", err)
	}
	if count("SELECT count(*) FROM cheesetrap.reports") != 2 {
		t.Fatal("new evidence did not produce late report")
	}
	// Restart/replay with no new evidence must never create another report.
	collect("", 12)
	process()
	for i := 0; i < 3; i++ {
		if _, err = draft.Next(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if count("SELECT count(*) FROM cheesetrap.reports") != 2 {
		t.Fatal("already-attributed evidence produced duplicate report")
	}

	if count("SELECT count(*) FROM cheesetrap.report_evidence e JOIN cheesetrap.reports r USING(report_id) WHERE r.window_id='"+third+"'") != 1 {
		t.Fatal("late report attached previously attributed evidence")
	}
	if count("SELECT count(*) FROM (SELECT event_id FROM cheesetrap.report_evidence GROUP BY event_id HAVING count(*)>1) duplicate") != 0 {
		t.Fatal("evidence attributed twice")
	}
	// Captured web GET is retained as a nonmatch. A second copy changes only the
	// request URI (and URI byte metadata) to an explicit synthetic exploit probe.
	webBytes, e := os.ReadFile("../../testdata/engines/web/events.jsonl")
	if e != nil {
		t.Fatal(e)
	}
	var webRecord map[string]any
	if json.Unmarshal([]byte(strings.Split(string(webBytes), "\n")[0]), &webRecord) != nil {
		t.Fatal("captured web record invalid")
	}
	webRecord["timestamp"] = observed.Format(time.RFC3339Nano)
	webRecord["peer_ip"] = "1.1.1.1"
	webRecord["destination_ip"] = "172.30.91.10"
	// Synthetic untrusted header and secret canary exercise rendering/redaction.
	canary := "<img src=x onerror=alert(1)>"
	headers := webRecord["headers"].([]any)
	headers = append(headers, map[string]any{"name": "user-agent", "value": canary}, map[string]any{"name": "authorization", "value": "Bearer private-test-canary"})
	webRecord["headers"] = headers
	headerBytes := 0
	for _, h := range headers {
		v := h.(map[string]any)
		headerBytes += len(v["name"].(string)) + len(v["value"].(string)) + 4
	}
	meta := webRecord["truncation"].(map[string]any)["headers"].(map[string]any)
	meta["observed"] = headerBytes
	meta["retained"] = headerBytes
	normal, _ := json.Marshal(webRecord)
	webRecord["uri"] = "/../etc/passwd"
	lengths := webRecord["truncation"].(map[string]any)["uri"].(map[string]any)
	lengths["observed"] = 13
	lengths["retained"] = 13
	attack, _ := json.Marshal(webRecord)
	source.SensorID = "10000000-0000-4000-8000-000000000708"
	source.Name = "review-web"
	source.Engine = "web"
	source.Path = "web.json"
	source.Endpoints = []ingestion.Endpoint{{Service: "http", ObservedIP: "172.30.91.10", ObservedPort: 8080, PublicIP: "192.0.2.10", PublicPort: 8080}}
	data, _ = json.Marshal([]ingestion.Source{source})
	if err = os.WriteFile(manifest, data, 0600); err != nil {
		t.Fatal(err)
	}
	log = filepath.Join(dir, "web.json")
	collect(string(normal)+"\n", 13)
	process()
	if count("SELECT count(*) FROM cheesetrap.detection_results WHERE rule_id='WEB-EXPLOIT'") != 0 {
		t.Fatal("normal captured web request became exploit")
	}
	collect(string(attack)+"\n", 14)
	process()
	var end4 time.Time
	if err = owner.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&end4); err != nil {
		t.Fatal(err)
	}
	fourth := newWindow(end3, end4)
	if ready, err = reporting.SealWindow(ctx, worker, fourth); err != nil || !ready {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		if _, err = draft.Next(ctx); err != nil {
			t.Fatal(err)
		}
	}
	var webReport string
	if err = owner.QueryRow(ctx, "SELECT report_id FROM cheesetrap.reports WHERE window_id=$1", fourth).Scan(&webReport); err != nil {
		t.Fatal("web exploit report missing", err)
	}
	if count("SELECT count(*) FROM cheesetrap.detection_results WHERE rule_id='WEB-EXPLOIT'") != 1 {
		t.Fatal("web exploit rule missing")
	}
	password := auth.RandomToken()
	if err = auth.NewService(pools["API"]).CreateAdmin(ctx, "review-admin", password); err != nil {
		t.Fatal(err)
	}
	var archivedID, archivedRevision, archivedOriginal, archivedEvidence string
	if err = owner.QueryRow(ctx, "SELECT r.report_id,r.current_revision_id,row_to_json(v)::text FROM cheesetrap.reports r JOIN cheesetrap.report_revisions v ON v.revision_id=r.current_revision_id WHERE r.window_id=$1", third).Scan(&archivedID, &archivedRevision, &archivedOriginal); err != nil {
		t.Fatal(err)
	}
	var approval string
	if err = owner.QueryRow(ctx, `INSERT INTO cheesetrap.approvals(report_id,revision_id,content_digest,admin_id,settings_version,schedule_version,approved_at,scheduled_at) SELECT r.report_id,r.current_revision_id,v.content_digest,a.admin_id,1,1,clock_timestamp(),clock_timestamp()+interval '1 hour' FROM cheesetrap.reports r JOIN cheesetrap.report_revisions v ON v.revision_id=r.current_revision_id CROSS JOIN cheesetrap.admins a WHERE r.report_id=$1 LIMIT 1 RETURNING approval_id::text`, archivedID).Scan(&approval); err != nil {
		t.Fatal(err)
	}
	for _, state := range []string{"queued", "sending"} {
		if _, err = owner.Exec(ctx, `UPDATE cheesetrap.reports SET state=$2,version=version+1 WHERE report_id=$1`, archivedID, state); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = owner.Exec(ctx, `INSERT INTO cheesetrap.delivery_attempts(report_id,revision_id,approval_id,attempt_number,message_id,phase,result,classification,started_at,finished_at) VALUES($1,$2,$3,1,'legacy@invalid','response','unknown','smtp_interrupted',clock_timestamp()-interval '1 second',clock_timestamp())`, archivedID, archivedRevision, approval); err != nil {
		t.Fatal(err)
	}
	for _, state := range []string{"unknown", "needs_review"} {
		if _, err = owner.Exec(ctx, `UPDATE cheesetrap.reports SET state=$2,version=version+1 WHERE report_id=$1`, archivedID, state); err != nil {
			t.Fatal(err)
		}
	}
	if err = owner.QueryRow(ctx, `SELECT jsonb_agg(to_jsonb(e) ORDER BY event_id)::text FROM cheesetrap.report_evidence e WHERE report_id=$1`, archivedID).Scan(&archivedEvidence); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(nil)
	origin := "http://" + server.Listener.Addr().String()
	server.Config.Handler = api.NewHandler(pools["API"], origin)
	server.Start()
	defer server.Close()
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 5 * time.Second}
	defer client.CloseIdleConnections()
	request := func(method, path, body, token string, want int) []byte {
		t.Helper()
		q, _ := http.NewRequestWithContext(ctx, method, origin+path, strings.NewReader(body))
		q.Header.Set("Origin", origin)
		q.Header.Set("Content-Type", "application/json")
		if token != "" {
			q.Header.Set("X-CSRF-Token", token)
		}
		resp, e := client.Do(q)
		if e != nil {
			t.Fatal("HTTP failed")
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != want {
			t.Fatalf("%s %s status=%d want=%d", method, path, resp.StatusCode, want)
		}
		return b
	}
	var csrf struct {
		Token string `json:"csrf_token"`
	}
	json.Unmarshal(request("GET", "/api/v1/auth/csrf", "", "", 200), &csrf)
	login, _ := json.Marshal(map[string]string{"username": "review-admin", "password": password})
	request("POST", "/api/v1/auth/login", string(login), "", 403)
	request("POST", "/api/v1/auth/login", string(login), csrf.Token, 200)
	events := request("GET", "/api/v1/events?source_ip=1.1.1.1", "", "", 200)
	if strings.Contains(string(events), "secret-password") || strings.Contains(string(events), "private-test-canary") {
		t.Fatal("API leaked engine credentials")
	}
	request("GET", "/api/v1/ips/1.1.1.1", "", "", 200)
	request("GET", "/api/v1/ips/198.51.100.20", "", "", 400)
	request("GET", "/api/v1/reports/"+reportID, "", "", 200)
	if os.Getenv("CHEESETRAP_E2E_RUN") == "1" {
		cmd := exec.CommandContext(ctx, "node", "node_modules/@playwright/test/cli.js", "test")
		cmd.Dir = "../../web"
		for _, key := range []string{"PATH", "HOME", "TMPDIR", "LANG"} {
			if value := os.Getenv(key); value != "" {
				cmd.Env = append(cmd.Env, key+"="+value)
			}
		}
		cmd.Env = append(cmd.Env, "CHEESETRAP_E2E_RUN=1", "CHEESETRAP_E2E_URL="+origin, "CHEESETRAP_E2E_PASSWORD="+password, "CHEESETRAP_E2E_REPORT="+reportID, "CHEESETRAP_E2E_WEB_REPORT="+webReport, "CHEESETRAP_E2E_ARCHIVED_REPORT="+archivedID)
		out, e := cmd.CombinedOutput()
		safe := strings.ReplaceAll(string(out), password, "[REDACTED]")
		t.Log(safe)
		if e != nil {
			t.Fatal("browser review failed")
		}
		if count("SELECT count(*) FROM cheesetrap.reports WHERE state='rejected'") != 1 {
			t.Fatal("browser rejection was not persisted")
		}
		var savedSettings bool
		if err = owner.QueryRow(ctx, `SELECT value->'retention'->>'event_days'='45' AND value->>'reply_to'='review@example.test' FROM cheesetrap.settings WHERE key='review_policy'`).Scan(&savedSettings); err != nil || !savedSettings {
			t.Fatal("browser settings save was not persisted", err)
		}
		var legacyAfter, evidenceAfter, currentRevision string
		if err = owner.QueryRow(ctx, `SELECT row_to_json(v)::text,r.current_revision_id FROM cheesetrap.reports r JOIN cheesetrap.report_revisions v ON v.revision_id=r.current_revision_id WHERE r.report_id=$1`, archivedID).Scan(&legacyAfter, &currentRevision); err != nil || legacyAfter != archivedOriginal || currentRevision != archivedRevision {
			t.Fatal("archived revision changed", err)
		}
		if err = owner.QueryRow(ctx, `SELECT jsonb_agg(to_jsonb(e) ORDER BY event_id)::text FROM cheesetrap.report_evidence e WHERE report_id=$1`, archivedID).Scan(&evidenceAfter); err != nil || evidenceAfter != archivedEvidence {
			t.Fatal("archived evidence changed", err)
		}
		if count("SELECT count(*) FROM cheesetrap_river.river_job WHERE kind IN ('deliver_report','smtp_test')") != 0 {
			t.Fatal("draft flow queued outbound job")
		}
		return
	}
	if count("SELECT count(*) FROM cheesetrap_river.river_job WHERE kind NOT IN ('detect_events','seal_window','draft_reports','refresh_contact')") != 0 {
		t.Fatal("unexpected outbound job")
	}
	t.Log("real collector/parser -> detection -> sealing -> RDAP mock transport -> drafts -> authenticated API; no SMTP client or send jobs invoked")
}
