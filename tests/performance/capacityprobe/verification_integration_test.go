//go:build integration

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"cheesetrap/internal/domain"
	"cheesetrap/internal/store"
	"cheesetrap/internal/store/db"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

func TestPinnedRevisionVerification(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := store.NewPool(ctx, os.Getenv("CHEESETRAP_TEST_REVISION_MIGRATION_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := tx.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	const eventID = "60000000-0000-4000-8000-000000000001"
	const absentID = "60000000-0000-4000-8000-999999999999"
	exec(`INSERT INTO cheesetrap.sensors(sensor_id,name,engine,public_ip,public_port) VALUES('10000000-0000-4000-8000-000000000600','probe-verification','cowrie','8.8.8.8',2222)`)
	exec(`INSERT INTO cheesetrap.file_generations(file_generation_id,sensor_id,path,device,inode) VALUES('20000000-0000-4000-8000-000000000600','10000000-0000-4000-8000-000000000600','/probe-verification',1,1)`)
	exec(`INSERT INTO cheesetrap.events(event_id,sensor_id,file_generation_id,byte_offset,ingestion_seq,schema_version,engine,observed_at,ingested_at,source_ip,service,event_type,raw_hash,is_test) VALUES($1,'10000000-0000-4000-8000-000000000600','20000000-0000-4000-8000-000000000600',1,6000001,1,'cowrie','2000-01-01','2000-01-02','1.1.1.1','ssh','cowrie.login.failed',repeat('a',64),true)`, eventID)
	exec(`INSERT INTO cheesetrap.detection_completions(ingestion_seq,event_id,rule_set_version) VALUES(6000001,$1,'1')`, eventID)
	var rule domain.ReportRule
	rule.RuleID, rule.RuleVersion, rule.SettingsVersion = "SSH-REPEAT", "1", "1"
	rule.ContextCount, rule.AttachedCount = 1, 1
	rule.EvidenceEligible, rule.AutoApprovalAllowed = true, true
	rule.Explanation = json.RawMessage(`{"n":9007199254740993,"nested":{"z":1,"a":2}}`)
	err = tx.QueryRow(ctx, `INSERT INTO cheesetrap.detection_results(rule_id,rule_version,processing_event_id,processing_ingestion_seq,source_ip,window_start,window_end,evidence_hash,evidence_count,evidence_eligible,auto_approval_allowed,explanation) VALUES('SSH-REPEAT','1',$1,6000001,'1.1.1.1','2000-01-01','2000-01-01',cheesetrap.evidence_set_hash(ARRAY[$1::uuid]),1,true,true,$2) RETURNING detection_id::text,evidence_hash`, eventID, rule.Explanation).Scan(&rule.DetectionID, &rule.EvidenceHash)
	if err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO cheesetrap.detection_evidence(detection_id,event_id) VALUES($1,$2)`, rule.DetectionID, eventID)
	var window pgtype.UUID
	if err := tx.QueryRow(ctx, `INSERT INTO cheesetrap.report_windows(start_at,end_at,settings_version,state,sealed_seq,sealed_at,ready_at) VALUES('2004-01-01','2004-01-02',1,'ready',6000001,'2004-01-02','2004-01-02') RETURNING window_id`).Scan(&window); err != nil {
		t.Fatal(err)
	}
	evidence := domain.ReportEvidence{EventID: eventID, IngestionSeq: 9007199254740993, ObservedAt: time.Date(2026, 10, 22, 1, 2, 3, 456, time.FixedZone("offset", 9*3600)), URI: "<&>日本語", QualityFlags: []string{}, CollectionGap: json.RawMessage(`{"n":9007199254740993,"dup":1,"dup":2}`)}
	snapshot := domain.ReportSnapshot{Evidence: []domain.ReportEvidence{evidence}, Rules: []domain.ReportRule{rule}}
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	copyJSON, err := json.Marshal(evidence)
	if err != nil {
		t.Fatal(err)
	}
	makeReport := func(t *testing.T, sub pgx.Tx, source string, raw []byte, body string) (string, string) {
		t.Helper()
		var report pgtype.UUID
		if err := sub.QueryRow(ctx, `INSERT INTO cheesetrap.reports(window_id,source_ip) VALUES($1,$2) RETURNING report_id`, window, source).Scan(&report); err != nil {
			t.Fatal(err)
		}
		rev, err := db.New(sub).AppendReportRevision(ctx, db.AppendReportRevisionParams{ReportID: report, Version: 1, Snapshot: raw, Subject: "subject", Body: body, HoldReasons: []string{"contact_missing"}, State: "held", ContentDigest: strings.Repeat("a", 64)})
		if err != nil {
			t.Fatal(err)
		}
		return report.String(), rev.String()
	}
	t.Run("copies", func(t *testing.T) {
		for _, mode := range []string{"exact", "missing_copy", "extra_copy", "changed_copy", "duplicate_evidence", "missing_revision", "wrong_report", "wrong_count", "empty_evidence", "null_evidence", "missing_evidence", "persisted_extension_fields"} {
			t.Run(mode, func(t *testing.T) {
				sub, err := tx.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer sub.Rollback(ctx)
				raw := encoded
				if mode == "duplicate_evidence" {
					s := snapshot
					s.Evidence = []domain.ReportEvidence{evidence, evidence}
					raw, _ = json.Marshal(s)
				}
				if mode == "empty_evidence" || mode == "null_evidence" || mode == "missing_evidence" {
					s := snapshot
					s.Evidence = []domain.ReportEvidence{}
					if mode != "empty_evidence" {
						s.Evidence = nil
					}
					raw, _ = json.Marshal(s)
					if mode == "missing_evidence" {
						if err := sub.QueryRow(ctx, `SELECT $1::jsonb-'evidence'`, raw).Scan(&raw); err != nil {
							t.Fatal(err)
						}
					}
				}
				if mode == "persisted_extension_fields" {
					if err := sub.QueryRow(ctx, `SELECT jsonb_set($1::jsonb,'{evidence,0,extension}', '"retained"'::jsonb)`, raw).Scan(&raw); err != nil {
						t.Fatal(err)
					}
				}
				id, revision := makeReport(t, sub, "1.1.1.1", raw, "body")
				copyValue := copyJSON
				if mode == "persisted_extension_fields" {
					if err := sub.QueryRow(ctx, `SELECT jsonb_set($1::jsonb,'{extension}', '"retained"'::jsonb)`, copyJSON).Scan(&copyValue); err != nil {
						t.Fatal(err)
					}
				}
				if mode == "changed_copy" {
					e := evidence
					e.URI = "changed"
					copyValue, _ = json.Marshal(e)
				}
				if mode != "missing_copy" && mode != "empty_evidence" && mode != "null_evidence" && mode != "missing_evidence" {
					if _, err := sub.Exec(ctx, `INSERT INTO cheesetrap.report_evidence(event_id,report_id,snapshot) VALUES($1,$2,$3)`, eventID, id, copyValue); err != nil {
						t.Fatal(err)
					}
				}
				if mode == "extra_copy" {
					if _, err := sub.Exec(ctx, `INSERT INTO cheesetrap.report_evidence(event_id,report_id,snapshot) VALUES($1::uuid,$2,jsonb_build_object('event_id',$1::uuid::text))`, absentID, id); err != nil {
						t.Fatal(err)
					}
				}
				count := 1
				if mode == "empty_evidence" || mode == "null_evidence" || mode == "missing_evidence" {
					count = 0
				}
				if mode == "duplicate_evidence" {
					count = 2
				}
				if mode == "wrong_count" {
					count = 0
				}
				if mode == "missing_revision" {
					id, revision, count = absentID, absentID, 0
				}
				if mode == "wrong_report" {
					id, count = absentID, 0
				}
				err = verifyRevisionCopies(ctx, sub, id, revision, count)
				if (err == nil) != (mode == "exact" || mode == "empty_evidence" || mode == "persisted_extension_fields") {
					t.Fatalf("mode=%s err=%v", mode, err)
				}
				if mode == "exact" || mode == "persisted_extension_fields" {
					// Deliberate oracle change: compare all stored fields. The old
					// typed projection dropped unknown fields before comparison,
					// so universal equivalence for extension data is not claimed.
					var typed domain.ReportSnapshot
					if err := json.Unmarshal(raw, &typed); err != nil {
						t.Fatal(err)
					}
					projected, err := json.Marshal(typed.Evidence)
					if err != nil {
						t.Fatal(err)
					}
					var mismatches int
					if err := sub.QueryRow(ctx, `WITH expected AS(SELECT value s FROM jsonb_array_elements($2::jsonb)),actual AS(SELECT snapshot s FROM cheesetrap.report_evidence WHERE report_id=$1) SELECT count(*) FROM expected x FULL JOIN actual a ON x.s->>'event_id'=a.s->>'event_id' WHERE x.s IS DISTINCT FROM a.s`, id, projected).Scan(&mismatches); err != nil {
						t.Fatal(err)
					}
					expectedMismatches := 0
					if mode == "persisted_extension_fields" {
						expectedMismatches = 1
					}
					if mismatches != expectedMismatches {
						t.Fatalf("old typed projection: mode=%s mismatches=%d want=%d", mode, mismatches, expectedMismatches)
					}
				}
			})
		}
	})
	t.Run("rules", func(t *testing.T) {
		changes := map[string]string{"exact": "", "detection_id": fmt.Sprintf("%q", absentID), "evidence_hash": `"changed"`, "context_count": "2", "rule_id": `"WEB-REPEAT"`, "rule_version": `"different"`, "explanation": `{"changed":true}`, "settings_version": `"2"`, "signature_id": `"changed"`, "signature_version": `"changed"`, "evidence_eligible": "false", "auto_approval_allowed": "false", "attached_count": "2", "missing_rules": "", "duplicate_rules": "", "missing_revision": "", "wrong_report": "", "wrong_count": "", "empty_rules": "", "null_rules": "", "absent_rules": ""}
		for name, value := range changes {
			t.Run(name, func(t *testing.T) {
				sub, err := tx.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer sub.Rollback(ctx)
				raw := encoded
				if value != "" {
					if err := sub.QueryRow(ctx, `SELECT jsonb_set($1::jsonb,ARRAY['rules','0',$2],$3::jsonb)`, encoded, name, value).Scan(&raw); err != nil {
						t.Fatal(err)
					}
				}
				if name == "missing_rules" {
					s := snapshot
					s.Rules = []domain.ReportRule{}
					raw, _ = json.Marshal(s)
				}
				if name == "duplicate_rules" {
					s := snapshot
					s.Rules = []domain.ReportRule{rule, rule}
					raw, _ = json.Marshal(s)
				}
				if name == "empty_rules" || name == "null_rules" || name == "absent_rules" {
					s := snapshot
					s.Rules = []domain.ReportRule{}
					if name != "empty_rules" {
						s.Rules = nil
					}
					raw, _ = json.Marshal(s)
					if name == "absent_rules" {
						if err := sub.QueryRow(ctx, `SELECT $1::jsonb-'rules'`, raw).Scan(&raw); err != nil {
							t.Fatal(err)
						}
					}
				}
				id, revision := makeReport(t, sub, "1.1.1.1", raw, "body")
				count := 1
				if name == "empty_rules" || name == "null_rules" || name == "absent_rules" {
					count = 0
				}
				if name == "duplicate_rules" {
					count = 2
				}
				if name == "wrong_count" {
					count = 0
				}
				if name == "missing_revision" {
					id, revision, count = absentID, absentID, 0
				}
				if name == "wrong_report" {
					id, count = absentID, 0
				}
				err = verifyRevisionRules(ctx, sub, id, revision, count)
				if (err == nil) != (name == "exact" || name == "empty_rules") {
					t.Fatalf("case=%s err=%v", name, err)
				}
			})
		}
	})
	t.Run("metadata_pins_current_revision", func(t *testing.T) {
		sub, err := tx.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer sub.Rollback(ctx)
		id, revision := makeReport(t, sub, "1.1.1.1", encoded, "current body")
		if _, err := sub.Exec(ctx, `UPDATE cheesetrap.reports SET current_revision_id=$2,version=1,state='held' WHERE report_id=$1`, id, revision); err != nil {
			t.Fatal(err)
		}
		var reportID pgtype.UUID
		if err := reportID.Scan(id); err != nil {
			t.Fatal(err)
		}
		if _, err := db.New(sub).AppendReportRevision(ctx, db.AppendReportRevisionParams{ReportID: reportID, Version: 2, Snapshot: encoded, Subject: "subject", Body: "not current body", HoldReasons: []string{"contact_missing"}, State: "held", ContentDigest: strings.Repeat("b", 64)}); err != nil {
			t.Fatal(err)
		}
		version, body, err := currentRevisionMetadata(ctx, sub, id)
		if err != nil || version != 1 || body != "current body" {
			t.Fatalf("version=%d body=%q err=%v", version, body, err)
		}
		if _, _, err := currentRevisionMetadata(ctx, sub, absentID); err == nil {
			t.Fatal("missing report accepted")
		}
	})
}
