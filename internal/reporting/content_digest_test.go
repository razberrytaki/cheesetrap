package reporting

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"runtime"
	"strings"
	"testing"
	"time"

	"cheesetrap/internal/domain"
)

// The pre-streaming algorithm is an independent compatibility oracle. Keep the
// whole-payload path here so tests cannot agree merely by sharing the new writer.
func wholePayloadContentDigest(r domain.ReportRevision) (string, error) {
	payload := struct {
		ReportID                          string                `json:"report_id"`
		Snapshot                          domain.ReportSnapshot `json:"snapshot"`
		Recipient, ReplyTo, Subject, Body string
		HoldReasons                       []string
		AutoApprovalAllowed               bool
	}{r.ReportID, r.Snapshot, r.Recipient, r.ReplyTo, r.Subject, r.Body, r.HoldReasons, r.AutoApprovalAllowed}
	data, err := json.Marshal(payload)
	if err != nil {
		return "", ErrRevisionInput
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var canonical any
	if decoder.Decode(&canonical) != nil {
		return "", ErrRevisionInput
	}
	data, err = json.Marshal(canonical)
	if err != nil {
		return "", ErrRevisionInput
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func TestContentDigestWholePayloadCompatibility(t *testing.T) {
	base := domain.ReportRevision{ReportID: "report\"<&\u2028", Recipient: "abuse@example.net", ReplyTo: "reply@example.net", Subject: "subject", Body: "body\n\t猫", HoldReasons: []string{"a", "b"}, AutoApprovalAllowed: true,
		Snapshot: domain.ReportSnapshot{SourceIP: "1.1.1.1", WindowID: "window", WindowStart: time.Date(2026, 10, 22, 1, 2, 3, 123456789, time.FixedZone("JST", 9*60*60)),
			Evidence: []domain.ReportEvidence{{EventID: "event", IngestionSeq: 9007199254740993, RawHash: "hash", QualityFlags: []string{}, FieldCompleteness: map[string]string{"z": "last", "a": "first"}, Truncation: map[string]domain.Truncation{"z": {Limit: 4096, Observed: 5000, Retained: 4096, Truncated: true}}, CollectionGap: json.RawMessage(`{"z":2,"a":1}`)}},
			Rules:    []domain.ReportRule{{DetectionID: "detection", RuleID: "WEB-EXPLOIT", RuleVersion: "1", SettingsVersion: "2", SignatureID: "signature", SignatureVersion: "3", ContextCount: 900, AttachedCount: 800, EvidenceHash: "hash", EvidenceEligible: true, Explanation: json.RawMessage(`{"z":2,"a":1}`)}},
			Registry: json.RawMessage(`{"z":2,"a":1}`)}}
	for _, tc := range []struct {
		name   string
		change func(*domain.ReportRevision)
	}{
		{"all_fields", func(*domain.ReportRevision) {}},
		{"nil_arrays", func(r *domain.ReportRevision) { r.Snapshot.Evidence = nil; r.Snapshot.Rules = nil; r.HoldReasons = nil }},
		{"empty_arrays", func(r *domain.ReportRevision) {
			r.Snapshot.Evidence = []domain.ReportEvidence{}
			r.Snapshot.Rules = []domain.ReportRule{}
			r.HoldReasons = []string{}
		}},
		{"empty_omitted_maps", func(r *domain.ReportRevision) {
			r.Snapshot.Evidence[0].FieldCompleteness = map[string]string{}
			r.Snapshot.Evidence[0].Truncation = map[string]domain.Truncation{}
			r.Snapshot.Evidence[0].CollectionGap = nil
			r.Snapshot.Rules[0].SettingsVersion = ""
		}},
		{"nil_optional_fields", func(r *domain.ReportRevision) {
			r.Snapshot.Evidence[0].FieldCompleteness = nil
			r.Snapshot.Evidence[0].Truncation = nil
			r.Snapshot.Evidence[0].QualityFlags = nil
			r.Snapshot.Rules[0].Explanation = nil
			r.Snapshot.Registry = nil
		}},
		{"nested_numbers_duplicate_keys", func(r *domain.ReportRevision) {
			raw := json.RawMessage(`{"z":0,"z":9007199254740993,"nested":[1e+09,1E-9,-0,1.2300,123456789012345678901234567890,{"b":true,"a":null}],"escaped":"<>&\u2028\ud800"}`)
			r.Snapshot.Registry = raw
			r.Snapshot.Rules[0].Explanation = raw
			r.Snapshot.Evidence[0].CollectionGap = raw
		}},
		{"raw_nonobjects", func(r *domain.ReportRevision) {
			r.Snapshot.Registry = json.RawMessage(`[true,false,null,{},[],"x",1]`)
			r.Snapshot.Rules[0].Explanation = json.RawMessage(`9007199254740993`)
			r.Snapshot.Evidence[0].CollectionGap = json.RawMessage(`"string"`)
		}},
		{"invalid_utf8_strings", func(r *domain.ReportRevision) {
			r.Body = "x\xffy"
			r.Snapshot.Evidence[0].EventID = "a\xffb"
			r.Snapshot.Evidence[0].FieldCompleteness = map[string]string{"a\xff": "b\xff"}
		}},
		{"invalid_registry", func(r *domain.ReportRevision) { r.Snapshot.Registry = json.RawMessage(`{"unfinished":`) }},
		{"invalid_explanation", func(r *domain.ReportRevision) { r.Snapshot.Rules[0].Explanation = json.RawMessage(`{"unfinished":`) }},
		{"invalid_collection_gap", func(r *domain.ReportRevision) {
			r.Snapshot.Evidence[0].CollectionGap = json.RawMessage(`{"unfinished":`)
		}},
		{"invalid_evidence_time", func(r *domain.ReportRevision) {
			r.Snapshot.Evidence[0].ObservedAt = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := base
			r.Snapshot.Evidence = append([]domain.ReportEvidence(nil), base.Snapshot.Evidence...)
			r.Snapshot.Rules = append([]domain.ReportRule(nil), base.Snapshot.Rules...)
			tc.change(&r)
			want, wantErr := wholePayloadContentDigest(r)
			got, gotErr := ContentDigest(r)
			if got != want || gotErr != wantErr {
				t.Fatalf("digest=%q error=%v, old=%q error=%v", got, gotErr, want, wantErr)
			}
		})
	}
}

func TestContentDigestLargeAllocationBudget(t *testing.T) {
	r := largeReportMemoryFixture()
	var err error
	r.Subject, r.Body, err = Render(r)
	if err != nil {
		t.Fatal(err)
	}
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	got, err := ContentDigest(r)
	runtime.ReadMemStats(&after)
	if err != nil {
		t.Fatal(err)
	}
	// This fixture renders the current template; historical stored digests are checked separately.
	const want = "5d2ff9592b68ddbe000118182779e9468c48ef04e07c4516f38b844bba60eff6"
	if got != want {
		t.Fatalf("large payload digest changed: %s", got)
	}
	// This portable allocation bound catches reconstructing the entire report as
	// maps and buffers (baseline ~620 MiB), independent of scheduler/GC timing.
	const budget = 512 * 1024 * 1024
	allocated := after.TotalAlloc - before.TotalAlloc
	t.Logf("large digest allocated=%d budget=%d", allocated, budget)
	if allocated > budget {
		t.Fatalf("large digest materializes whole payload: allocated %d bytes, budget %d", allocated, budget)
	}
	runtime.KeepAlive(r)
}

func TestContentDigestLongElementCompatibility(t *testing.T) {
	r := domain.ReportRevision{Snapshot: domain.ReportSnapshot{Evidence: []domain.ReportEvidence{{Command: strings.Repeat("猫<&", 16000)}}}}
	want, err := wholePayloadContentDigest(r)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ContentDigest(r)
	if err != nil || got != want {
		t.Fatal("long element digest changed", err)
	}
}
