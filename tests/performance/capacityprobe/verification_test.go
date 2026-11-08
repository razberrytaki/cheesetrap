package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"runtime"
	"strings"
	"testing"
	"time"

	"cheesetrap/internal/domain"
)

func TestEvidenceHashMatchesWholeArray(t *testing.T) {
	rich := domain.ReportEvidence{EventID: "first", IngestionSeq: 9007199254740993, ObservedAt: time.Date(2026, 10, 22, 1, 2, 3, 456, time.FixedZone("offset", 9*3600)), URI: "<&>\u2028日本語", QualityFlags: []string{}, FieldCompleteness: map[string]string{"z": "present", "a": "missing"}, CollectionGap: json.RawMessage(` {"n":9007199254740993,"dup":1,"dup":2,"nested":[1e3,1.00,-0]} `)}
	invalidUTF := rich
	invalidUTF.URI = string([]byte{0xff, 'x'})
	badJSON := rich
	badJSON.CollectionGap = json.RawMessage(`{"unfinished":`)
	badTime := rich
	badTime.ObservedAt = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		name string
		rows []domain.ReportEvidence
	}{
		{"nil", nil}, {"empty", []domain.ReportEvidence{}}, {"rich", []domain.ReportEvidence{rich}},
		{"order", []domain.ReportEvidence{{EventID: "second"}, rich}}, {"reverse", []domain.ReportEvidence{rich, {EventID: "second"}}},
		{"invalid_utf8", []domain.ReportEvidence{invalidUTF}}, {"late_invalid_json", []domain.ReportEvidence{rich, badJSON}}, {"late_invalid_time", []domain.ReportEvidence{rich, badTime}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			encoded, oldErr := json.Marshal(tc.rows)
			got, err := evidenceSHA256(tc.rows)
			if oldErr != nil {
				if err == nil || got != "" {
					t.Fatalf("invalid array returned hash=%q err=%v", got, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(encoded)
			if got != hex.EncodeToString(sum[:]) {
				t.Fatal("evidence SHA changed")
			}
		})
	}
}

func TestEvidenceHashAllocationBound(t *testing.T) {
	rows := make([]domain.ReportEvidence, 256)
	for i := range rows {
		rows[i] = domain.ReportEvidence{EventID: "event", URI: strings.Repeat("x", 64<<10)}
	}
	element, err := json.Marshal(rows[0])
	if err != nil {
		t.Fatal(err)
	}
	encodedSize := len(rows)*(len(element)+1) + 1
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	if _, err := evidenceSHA256(rows); err != nil {
		t.Fatal(err)
	}
	runtime.ReadMemStats(&after)
	allocated := after.TotalAlloc - before.TotalAlloc
	// Race builds can discard pooled JSON buffers; allow that overhead while
	// rejecting the measured whole-array allocation (over six array sizes).
	budget := uint64(encodedSize)*5/2 + (1 << 20)
	t.Logf("array_bytes=%d allocated=%d budget=%d", encodedSize, allocated, budget)
	if allocated > budget {
		t.Fatalf("evidence hash allocated %d bytes, want <=%d without a whole-array buffer", allocated, budget)
	}
	runtime.KeepAlive(rows)
}
