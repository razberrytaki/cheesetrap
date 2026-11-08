package reporting

import (
	"bytes"
	"cheesetrap/internal/domain"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"
)

func TestMarshalReportSnapshotCompatibility(t *testing.T) {
	raw := json.RawMessage(` {"z":1,"z":9007199254740993,"a":[1e+09,-0,1.2300,"<>&\u2028\ud800"]} `)
	complete := domain.ReportSnapshot{SourceIP: "1.1.1.1", WindowID: "window", WindowStart: time.Date(2026, 10, 22, 1, 2, 3, 456, time.FixedZone("JST", 9*3600)), Registry: raw,
		Evidence: []domain.ReportEvidence{{EventID: "event", IngestionSeq: 9007199254740993, Command: strings.Repeat("猫<&", 4000), QualityFlags: []string{}, CollectionGap: raw, FieldCompleteness: map[string]string{"z": "last", "a": "first", "bad\xff": "x\xff"}, Truncation: map[string]domain.Truncation{"uri": {Limit: 100, Observed: 200, Retained: 100, Truncated: true}}}},
		Rules:    []domain.ReportRule{{DetectionID: "detection", SettingsVersion: "1", RuleID: "WEB-REPEAT", RuleVersion: "1", ContextCount: 200, AttachedCount: 150, EvidenceEligible: true, AutoApprovalAllowed: true, Explanation: raw}}}
	for _, tc := range []struct {
		name     string
		snapshot domain.ReportSnapshot
	}{
		{"complete", complete},
		{"nil_arrays", domain.ReportSnapshot{}},
		{"empty_arrays", domain.ReportSnapshot{Evidence: []domain.ReportEvidence{}, Rules: []domain.ReportRule{}}},
		{"empty_elements", domain.ReportSnapshot{Evidence: []domain.ReportEvidence{{}, {}}, Rules: []domain.ReportRule{{}, {}}}},
		{"raw_scalar_values", domain.ReportSnapshot{Registry: []byte(`9007199254740993`), Evidence: []domain.ReportEvidence{{CollectionGap: []byte(`"string"`)}}, Rules: []domain.ReportRule{{Explanation: []byte(`[null,true,1.00]`)}}}},
		{"invalid_registry", domain.ReportSnapshot{Registry: []byte(`{"x":`)}},
		{"invalid_evidence", domain.ReportSnapshot{Evidence: []domain.ReportEvidence{{}, {CollectionGap: []byte(`{"x":`)}}}},
		{"invalid_rule", domain.ReportSnapshot{Rules: []domain.ReportRule{{}, {Explanation: []byte(`{"x":`)}}}},
		{"invalid_time", domain.ReportSnapshot{Evidence: []domain.ReportEvidence{{ObservedAt: time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want, wantErr := json.Marshal(tc.snapshot)
			got, gotErr := marshalReportSnapshot(tc.snapshot)
			if (gotErr != nil) != (wantErr != nil) || !bytes.Equal(got, want) {
				t.Fatalf("snapshot bytes/error differ: got=%q err=%v want=%q err=%v", got, gotErr, want, wantErr)
			}
		})
	}
}

// Distinct elements catch omission, duplication and reordering without a large fixture.
func TestMarshalReportSnapshotMultipleElementsCompatibility(t *testing.T) {
	snapshot := domain.ReportSnapshot{
		Evidence: []domain.ReportEvidence{{EventID: "first", IngestionSeq: 3}, {EventID: "second", IngestionSeq: 1}, {EventID: "third", IngestionSeq: 2}},
		Rules:    []domain.ReportRule{{DetectionID: "third"}, {DetectionID: "first"}, {DetectionID: "second"}},
	}
	want, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	got, err := marshalReportSnapshot(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("multi-element snapshot JSON bytes changed")
	}
}

func BenchmarkLargeReportSnapshotMarshal(b *testing.B) {
	r := largeReportMemoryFixture()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := marshalReportSnapshot(r.Snapshot); err != nil {
			b.Fatal(err)
		}
	}
}

func TestSnapshotOutputBounds(t *testing.T) {
	size := snapshotJSONSize{n: int(^uint(0)>>1) - 1}
	if _, err := size.Write([]byte("xx")); err == nil {
		t.Fatal("size counter overflow accepted")
	}
	output := snapshotJSONOutput{data: make([]byte, 1)}
	if _, err := output.Write([]byte("xx")); err != io.ErrShortWrite || output.n != 0 {
		t.Fatal("fixed output silently grew", err)
	}
	if err := writeSnapshotBytes(&output, []byte("x")); err != nil || string(output.data) != "x" {
		t.Fatal("exact output write failed", err)
	}
}
