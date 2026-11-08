//go:build integration

package reporting

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"cheesetrap/internal/detection"
	"cheesetrap/internal/domain"
	"cheesetrap/internal/enrichment"
	"cheesetrap/internal/store"
	"cheesetrap/internal/store/db"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestReportRevision(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	pools := map[string]*pgxpool.Pool{}
	for _, role := range []string{"MIGRATION", "WORKER", "API", "COLLECTOR"} {
		p, err := store.NewPool(ctx, os.Getenv("CHEESETRAP_TEST_REVISION_"+role+"_URL"))
		if err != nil {
			t.Fatal(err)
		}
		defer p.Close()
		pools[role] = p
	}
	owner, worker, api := pools["MIGRATION"], pools["WORKER"], pools["API"]
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := owner.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	var now time.Time
	if err := owner.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&now); err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO cheesetrap.sensors(sensor_id,name,engine,public_ip,public_port) VALUES('10000000-0000-4000-8000-000000000404','revision','cowrie','8.8.8.8',2222)`)
	exec(`INSERT INTO cheesetrap.file_generations(file_generation_id,sensor_id,path,device,inode) VALUES('20000000-0000-4000-8000-000000000404','10000000-0000-4000-8000-000000000404','/fixture',1,1)`)
	exec(`INSERT INTO cheesetrap.events(sensor_id,file_generation_id,byte_offset,ingestion_seq,schema_version,engine,observed_at,ingested_at,source_ip,source_port,destination_ip,destination_port,service,event_type,attributes,raw_hash) SELECT '10000000-0000-4000-8000-000000000404','20000000-0000-4000-8000-000000000404',n,n,1,CASE WHEN n<=10 THEN 'cowrie' ELSE 'web' END,$1::timestamptz+n*interval '1 second',$1,'1.1.1.1',12345,'8.8.8.8',CASE WHEN n<=10 THEN 2222 ELSE 8080 END,CASE WHEN n<=10 THEN 'ssh' ELSE 'http' END,CASE WHEN n<=10 THEN 'cowrie.login.failed' ELSE 'web.request' END,CASE WHEN n<=10 THEN '{"password":"TOP_SECRET","headers":[{"name":"authorization","value":"TOP_SECRET"}],"body":"TOP_SECRET"}'::jsonb ELSE jsonb_build_object('method','GET','uri',CASE WHEN n=31 THEN '/../../etc/passwd' ELSE (ARRAY['/.env','/.git/config','/wp-login.php','/wp-admin','/phpmyadmin'])[1+(n%5)] END) END,repeat('a',64) FROM generate_series(1,31)n`, now.Add(-time.Hour))
	exec("UPDATE cheesetrap.processing_cursors SET ingested_seq=31")
	if _, err := detection.ProcessBatch(ctx, worker, 1000); err != nil {
		t.Fatal(err)
	}
	var window string
	if err := owner.QueryRow(ctx, `INSERT INTO cheesetrap.report_windows(start_at,end_at,settings_version,state,sealed_seq,sealed_at,ready_at) VALUES($1,$2,1,'ready',31,$2,$2) RETURNING window_id`, now.Add(-2*time.Hour), now.Add(-30*time.Minute)).Scan(&window); err != nil {
		t.Fatal(err)
	}
	t.Run("exact_chunk_read_compatibility", func(t *testing.T) { verifyChunkReadCompatibility(t, ctx, owner, window) })
	contact := enrichment.Result{SchemaVersion: 1, Address: "1.1.1.1", LookupSucceeded: true, QueriedAt: now, ExpiresAt: now.Add(time.Hour), HeldReason: "contact_ambiguous"}
	for _, email := range []string{"abuse@example.net", "security@example.net"} {
		contact.Candidates = append(contact.Candidates, enrichment.Contact{Email: email, Role: "abuse", Method: "rdap", SourceURL: "https://rdap.example.net/ip/1.1.1.1", NetworkStart: "1.1.1.0", NetworkEnd: "1.1.1.255", Sources: []enrichment.Source{{Role: "abuse", Method: "rdap", SourceURL: "https://rdap.example.net/ip/1.1.1.1", NetworkStart: "1.1.1.0", NetworkEnd: "1.1.1.255"}}})
	}
	data, _ := json.Marshal(contact)
	exec(`INSERT INTO cheesetrap.enrichment_cache(address,result,queried_at,expires_at) VALUES('1.1.1.1',$1,$2,$3)`, data, now, now.Add(time.Hour))
	t.Run("earlier_sealed_window_blocks_later_ready", func(t *testing.T) {
		var earlier string
		if err := owner.QueryRow(ctx, `INSERT INTO cheesetrap.report_windows(start_at,end_at,settings_version,state,sealed_seq,sealed_at) VALUES($1,$2,1,'sealed',0,$2) RETURNING window_id`, now.Add(-3*time.Hour), now.Add(-2*time.Hour)).Scan(&earlier); err != nil {
			t.Fatal(err)
		}
		progress, err := DraftNext(ctx, worker)
		if err != nil || progress.Processed || !progress.More {
			t.Fatal("later ready window bypassed prior sealed window", err)
		}
		var n int
		if err = owner.QueryRow(ctx, "SELECT count(*) FROM cheesetrap.reports").Scan(&n); err != nil || n != 0 {
			t.Fatal("later ready window claimed evidence")
		}
		if ready, err := SealWindow(ctx, worker, earlier); err != nil || !ready {
			t.Fatal(err)
		}
		if progress, err = DraftNext(ctx, worker); err != nil || !progress.Processed {
			t.Fatal("empty earlier window not completed", err)
		}
	})
	t.Run("atomic_copy_revision_and_candidate", func(t *testing.T) {
		exec(`CREATE FUNCTION cheesetrap.test_fail_report_candidate() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected'; END $$; CREATE TRIGGER test_fail_report_candidate BEFORE INSERT ON cheesetrap.report_candidates FOR EACH ROW EXECUTE FUNCTION cheesetrap.test_fail_report_candidate()`)
		_, err := DraftNext(ctx, worker)
		exec("DROP TRIGGER test_fail_report_candidate ON cheesetrap.report_candidates; DROP FUNCTION cheesetrap.test_fail_report_candidate()")
		if !errors.Is(err, ErrRevisionFailed) {
			t.Fatal("late transaction failure not returned", err)
		}
		for _, table := range []string{"reports", "report_evidence", "report_revisions", "report_candidates"} {
			var n int
			if err := owner.QueryRow(ctx, "SELECT count(*) FROM cheesetrap."+table).Scan(&n); err != nil || n != 0 {
				t.Fatal("failed transaction published partial report", table, err)
			}
		}
	})
	t.Run("aggregate_and_concurrent_retry", func(t *testing.T) {
		var wg sync.WaitGroup
		for range 2 {
			wg.Go(func() {
				if _, err := DraftNext(ctx, worker); err != nil {
					t.Error(err)
				}
			})
		}
		wg.Wait()
	})
	var reportID string
	if err := owner.QueryRow(ctx, "SELECT report_id FROM cheesetrap.reports WHERE source_ip='1.1.1.1'").Scan(&reportID); err != nil {
		t.Fatal(err)
	}
	first, err := LoadRevision(ctx, api, reportID)
	if err != nil {
		t.Fatal(err)
	}
	if sum, err := ContentDigest(first); err != nil || sum != first.ContentDigest {
		t.Fatal("digest failed JSONB roundtrip", err)
	}
	if e, r := first.Snapshot.Counts(); e != 31 || r < 3 || first.State != "held" {
		t.Fatalf("aggregation failed: evidence=%d rules=%d state=%s", e, r, first.State)
	}
	for _, hold := range []string{"contact_ambiguous", "reply_to_missing"} {
		if !slices.Contains(first.HoldReasons, hold) {
			t.Errorf("missing hold %s: %v", hold, first.HoldReasons)
		}
	}
	if strings.Contains(first.Body, "TOP_SECRET") {
		t.Fatal("secret copied into body")
	}
	snapshot, _ := json.Marshal(first.Snapshot)
	if strings.Contains(string(snapshot), "TOP_SECRET") {
		t.Fatal("secret copied into snapshot")
	}
	t.Run("revision_changes_and_optimistic_version", func(t *testing.T) {
		if err := SetReplyTo(ctx, api, "operator@example.org"); err != nil {
			t.Fatal(err)
		}
		recipient, body := "abuse@example.net", first.Body+"\nOperator review note.\n"
		second, err := ChangeRevision(ctx, api, reportID, 1, RevisionChanges{Recipient: &recipient, Body: &body})
		if err != nil {
			t.Fatal(err)
		}
		if second.AutoApprovalAllowed || second.State != "needs_review" || second.Version != 2 || second.ContentDigest == first.ContentDigest || second.Body != body || second.Recipient != recipient || second.ReplyTo != "operator@example.org" || slices.Contains(second.HoldReasons, "contact_ambiguous") || slices.Contains(second.HoldReasons, "reply_to_missing") {
			t.Fatal("new revision did not bind changed contents")
		}
		if _, err = ChangeRevision(ctx, api, reportID, 1, RevisionChanges{Body: &body}); !errors.Is(err, ErrRevisionConflict) {
			t.Fatal("lost update allowed", err)
		}
		invalid := "invented@example.net"
		if _, err = ChangeRevision(ctx, api, reportID, 2, RevisionChanges{Recipient: &invalid}); !errors.Is(err, ErrRevisionInput) {
			t.Fatal("unverified recipient allowed", err)
		}
		var persisted string
		if err = owner.QueryRow(ctx, "SELECT content_digest FROM cheesetrap.report_revisions WHERE revision_id=$1", first.RevisionID).Scan(&persisted); err != nil || persisted != first.ContentDigest {
			t.Fatal("old revision changed")
		}
	})
	t.Run("immutable_roles_and_pointer_ownership", func(t *testing.T) {
		for _, table := range []string{"reports", "report_evidence", "report_revisions"} {
			if _, err := pools["COLLECTOR"].Exec(ctx, "SELECT * FROM cheesetrap."+table+" LIMIT 1"); err == nil {
				t.Fatal("collector can read report data", table)
			}
		}
		_, err := owner.Exec(ctx, `INSERT INTO cheesetrap.reports(window_id,source_ip,version,current_revision_id,state) VALUES($1,'9.9.9.10',1,$2,'held')`, uuid(window), uuid(first.RevisionID))
		var pgerr *pgconn.PgError
		if !errors.As(err, &pgerr) || pgerr.Code != "23503" {
			t.Fatal("cross-report pointer did not fail composite ownership FK", err)
		}
		for _, role := range []string{"WORKER", "API", "COLLECTOR"} {
			for _, sql := range []string{"UPDATE cheesetrap.report_revisions SET body='changed'", "DELETE FROM cheesetrap.report_evidence"} {
				if _, err := pools[role].Exec(ctx, sql); err == nil {
					t.Fatalf("%s mutated immutable record", role)
				}
			}
		}
		if _, err := owner.Exec(ctx, "UPDATE cheesetrap.report_revisions SET body='changed'"); err == nil {
			t.Fatal("owner update bypassed immutability")
		}
	})
	t.Run("duplicate_only_candidate_and_chronology", func(t *testing.T) {
		// A later trigger may carry only previously assigned context; it cannot create a report.
		exec(`INSERT INTO cheesetrap.events(sensor_id,file_generation_id,byte_offset,ingestion_seq,schema_version,engine,observed_at,ingested_at,source_ip,service,event_type,raw_hash) VALUES('10000000-0000-4000-8000-000000000404','20000000-0000-4000-8000-000000000404',32,32,1,'cowrie',$1,$2,'1.1.1.1','ssh','session.connect',repeat('a',64))`, now.Add(-time.Hour), now.Add(-20*time.Minute))
		exec("UPDATE cheesetrap.processing_cursors SET ingested_seq=32")
		if _, err := detection.ProcessBatch(ctx, worker, 1000); err != nil {
			t.Fatal(err)
		}
		var later string
		if err := owner.QueryRow(ctx, `INSERT INTO cheesetrap.report_windows(start_at,end_at,settings_version,state,sealed_seq,sealed_at,ready_at) VALUES($1,$2,1,'ready',32,$2,$2) RETURNING window_id`, now.Add(-30*time.Minute), now.Add(-10*time.Minute)).Scan(&later); err != nil {
			t.Fatal(err)
		}
		exec(`WITH d AS (INSERT INTO cheesetrap.detection_results(rule_id,rule_version,processing_event_id,processing_ingestion_seq,source_ip,window_start,window_end,evidence_hash,evidence_count,evidence_eligible,auto_approval_allowed,explanation) SELECT 'SSH-REPEAT','1',event_id,32,'1.1.1.1',$1,$1,repeat('b',64),10,true,true,'{"count":10}' FROM cheesetrap.events WHERE ingestion_seq=32 RETURNING detection_id) INSERT INTO cheesetrap.detection_evidence SELECT d.detection_id,e.event_id FROM d CROSS JOIN cheesetrap.events e WHERE e.ingestion_seq<=10`, now.Add(-time.Hour))
		for range 4 {
			if _, err := DraftNext(ctx, worker); err != nil {
				t.Fatal(err)
			}
		}
		var n int
		if err := owner.QueryRow(ctx, "SELECT count(*) FROM cheesetrap.reports").Scan(&n); err != nil || n != 1 {
			t.Fatal("duplicate-only candidate created report")
		}
		if err := owner.QueryRow(ctx, "SELECT count(*) FROM cheesetrap.report_candidates WHERE window_id=$1 AND outcome='already_assigned'", later).Scan(&n); err != nil || n != 1 {
			t.Fatal("duplicate-only outcome not durable", err)
		}
	})
	t.Run("new_candidate_owns_only_unassigned_context", func(t *testing.T) {
		exec(`INSERT INTO cheesetrap.events(sensor_id,file_generation_id,byte_offset,ingestion_seq,schema_version,engine,observed_at,ingested_at,source_ip,destination_ip,destination_port,service,event_type,raw_hash) VALUES('10000000-0000-4000-8000-000000000404','20000000-0000-4000-8000-000000000404',33,33,1,'cowrie',$1,$2,'1.1.1.1','8.8.8.8',2222,'ssh','cowrie.login.failed',repeat('a',64))`, now.Add(-58*time.Minute), now.Add(-5*time.Minute))
		exec("UPDATE cheesetrap.processing_cursors SET ingested_seq=33")
		if _, err := detection.ProcessBatch(ctx, worker, 1000); err != nil {
			t.Fatal(err)
		}
		var later string
		if err := owner.QueryRow(ctx, `INSERT INTO cheesetrap.report_windows(start_at,end_at,settings_version,state,sealed_seq,sealed_at,ready_at) VALUES($1,$2,1,'ready',33,$2,$2) RETURNING window_id`, now.Add(-10*time.Minute), now.Add(-time.Minute)).Scan(&later); err != nil {
			t.Fatal(err)
		}
		for range 3 {
			if _, err := DraftNext(ctx, worker); err != nil {
				t.Fatal(err)
			}
		}
		var id string
		if err := owner.QueryRow(ctx, "SELECT report_id FROM cheesetrap.reports WHERE window_id=$1", later).Scan(&id); err != nil {
			t.Fatal(err)
		}
		r, err := LoadRevision(ctx, api, id)
		if err == nil {
			r = materializeRevisionForTest(t, r)
		}
		if err != nil || len(r.Snapshot.Evidence) != 1 || len(r.Snapshot.Rules) != 1 || r.Snapshot.Rules[0].ContextCount != 11 || r.Snapshot.Rules[0].AttachedCount != 1 || !r.Snapshot.DelayedCollection {
			t.Fatal("new ownership confused with overlapping rule context", err)
		}
		var n int
		if err = owner.QueryRow(ctx, "SELECT count(*) FROM cheesetrap.report_evidence").Scan(&n); err != nil || n != 32 {
			t.Fatal("global attribution duplicated")
		}
	})
	t.Run("policy_stale_quality_and_verified_expiry", func(t *testing.T) {
		r := first
		r = materializeRevisionForTest(t, r)
		r.Recipient = "abuse@example.net"
		r.Snapshot.Evidence = append([]domain.ReportEvidence(nil), r.Snapshot.Evidence...)
		r.Snapshot.Evidence[0].QualityFlags = []string{"credentials_redacted", "body_redacted", "headers_redacted", "uri_redacted", "command_redacted"}
		if err := prepareRevision(ctx, db.New(api), &r, nil); err != nil || r.State != "needs_review" {
			t.Fatal("benign redactions/manual signature incorrectly held", err, r.HoldReasons)
		}
		r.Snapshot.ObservedEnd = now.Add(-73 * time.Hour)
		r.Snapshot.Evidence[0].QualityFlags = []string{"collection_gap"}
		r.Snapshot.Evidence[0].CollectionGap = []byte(`{"started_at":"2026-01-01T00:00:00Z"}`)
		if err := prepareRevision(ctx, db.New(api), &r, nil); err != nil || !slices.Contains(r.HoldReasons, "stale_evidence") || !slices.Contains(r.HoldReasons, "collection_gap") {
			t.Fatal("stale/gap holds missing", err, r.HoldReasons)
		}
		expired := contact
		expired.ExpiresAt = now.Add(-time.Second)
		r.Snapshot.Registry, _ = json.Marshal(expired)
		selected := "abuse@example.net"
		if err := prepareRevision(ctx, db.New(api), &r, &selected); !errors.Is(err, ErrRevisionInput) {
			t.Fatal("expired verified recipient selected", err)
		}
		expired.Address = "9.9.9.9"
		expired.ExpiresAt = now.Add(time.Hour)
		r.Snapshot.Registry, _ = json.Marshal(expired)
		if err := prepareRevision(ctx, db.New(api), &r, &selected); !errors.Is(err, ErrRevisionInput) {
			t.Fatal("different-IP contact selected", err)
		}
	})
	t.Run("generated_body_tracks_reply_address", func(t *testing.T) {
		// Prepare a distinct report using the same frozen content to exercise the
		// autogenerated-body path independently of the deliberately custom revision.
		r := materializeRevisionForTest(t, first)
		r.ReplyTo = ""
		r.Recipient = "abuse@example.net"
		tx, err := owner.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(context.Background())
		q := db.New(tx)
		report, err := q.CreateReport(ctx, db.CreateReportParams{WindowID: uuid(window), SourceIp: netip.MustParseAddr("9.9.9.9")})
		if err != nil {
			t.Fatal(err)
		}
		r.ReportID = report.ReportID.String()
		r.RevisionID = ""
		r.Version = 1
		r.Subject, r.Body, err = Render(r)
		if err != nil {
			t.Fatal(err)
		}
		if err = appendRevision(ctx, q, &r, 0); err != nil {
			t.Fatal(err)
		}
		if err = tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		revised, err := ChangeRevision(ctx, api, r.ReportID, 1, RevisionChanges{})
		if err != nil || !strings.Contains(revised.Body, "Contact: operator@example.org") {
			t.Fatal("generated body retained old reply address", err)
		}
		if _, err = owner.Exec(ctx, "UPDATE cheesetrap.reports SET current_revision_id=$1 WHERE report_id=$2", uuid(first.RevisionID), report.ReportID); err == nil {
			t.Fatal("cross-report revision pointer accepted")
		}
	})
	t.Run("retention_preserves_copies", func(t *testing.T) {
		before, err := LoadRevision(ctx, api, reportID)
		if err != nil {
			t.Fatal(err)
		}
		// Fixture-only removal, not the unfinished Task 3 retention implementation.
		exec("TRUNCATE cheesetrap.detection_evidence, cheesetrap.detection_evidence_chunks, cheesetrap.evidence_chunk_members, cheesetrap.evidence_chunks, cheesetrap.detection_results, cheesetrap.detection_completions; DELETE FROM cheesetrap.events")
		after, err := LoadRevision(ctx, api, reportID)
		evidenceCount, _ := after.Snapshot.Counts()
		if err != nil || after.ContentDigest != before.ContentDigest || evidenceCount != 31 {
			t.Fatal("retention destroyed snapshot", err)
		}
	})
	_ = domain.ReportRevision{}
}
