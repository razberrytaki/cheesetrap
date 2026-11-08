package web

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func webFixture(t *testing.T) (Fixture, []byte, map[string][]byte) {
	t.Helper()
	raw, e := os.ReadFile("../../../testdata/engines/web/events.jsonl")
	if e != nil {
		t.Fatal(e)
	}
	b, e := os.ReadFile("../../../testdata/engines/web/expected.json")
	if e != nil {
		t.Fatal(e)
	}
	var f Fixture
	if e = json.Unmarshal(b, &f); e != nil {
		t.Fatal(e)
	}
	inputs := map[string][]byte{}
	cases, e := LoadCases("../../../testdata/engines/web/cases.json")
	if e != nil {
		t.Fatal(e)
	}
	cases = append(cases, SupplementalCases()...)
	for _, c := range cases {
		b, e = c.Bytes("m0.test.invalid")
		if e != nil {
			t.Fatal(e)
		}
		inputs[c.ID] = b
	}
	return f, raw, inputs
}
func TestWebFixture(t *testing.T) {
	f, raw, inputs := webFixture(t)
	if f.Kind != "sanitized-real-engine-run" || len(f.OriginalRawSHA256) != 64 || len(f.OriginalRunSHA256) != 64 || len(f.OriginalLineSHA256) != bytes.Count(raw, []byte("\n")) || Hash(raw) != f.SHA256 || len(f.Redactions) < 5 {
		t.Fatal("missing real-run provenance")
	}
	if bytes.Contains(raw, []byte("m0-secret")) {
		t.Fatal("secret leaked into public fixture")
	}
	cases, e := os.ReadFile("../../../testdata/engines/web/cases.json")
	if e != nil || Hash(cases) != f.CasesSHA256 {
		t.Fatal("case specification hash mismatch")
	}
	if len(f.ImageInspectSHA256) != 64 || len(f.BuildInputs) != 6 {
		t.Fatal("missing inspected-image/build provenance")
	}
	if len(f.CurrentBuildInputs) != len(f.BuildInputs) {
		t.Fatal("missing current build inputs")
	}
	for path, hash := range f.CurrentBuildInputs {
		b, e := os.ReadFile(filepath.Join("../../..", path))
		if e != nil || Hash(b) != hash {
			t.Fatal("build input changed:", path)
		}
	}
	got := Validate(f.Run, raw, inputs)
	if got.Status != "PASS" || !reflect.DeepEqual(got, f.Report) {
		for i := range got.Results {
			if !reflect.DeepEqual(got.Results[i], f.Report.Results[i]) {
				t.Fatalf("fixture case %s differs: quality got=%#v expected=%#v", got.Results[i].CaseID, got.Results[i].Quality, f.Report.Results[i].Quality)
			}
		}
		t.Fatalf("fixture evidence differs: %s", got.Reason)
	}
}
func TestWebEvidenceRejectsTampering(t *testing.T) {
	changes := map[string]func(*Event){
		"forged peer":                     func(e *Event) { e.PeerIP = "203.0.113.99" },
		"missing peer port":               func(e *Event) { e.PeerPort = 0 },
		"wrong destination":               func(e *Event) { e.DestinationPort = 80 },
		"missing method":                  func(e *Event) { e.Method = nil },
		"wrong query":                     func(e *Event) { v := "/wrong?q=lost"; e.URI = &v },
		"wrong headers":                   func(e *Event) { v := []Header{}; e.Headers = &v },
		"wrong body":                      func(e *Event) { v := "invented body"; e.Body = &v },
		"wire hash mismatch":              func(e *Event) { e.WireSHA256 = "invalid" },
		"invented byte count":             func(e *Event) { e.WireBytes = 999999 },
		"parse flag missing":              func(e *Event) { e.ParseError = nil },
		"truncation missing":              func(e *Event) { delete(e.Truncation, "body") },
		"auto report incorrectly enabled": func(e *Event) { e.AutoReportEligible = true },
		"stale timestamp":                 func(e *Event) { e.Timestamp = "2000-01-01T00:00:00Z" },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			f, raw, inputs := webFixture(t)
			lines := bytes.Split(bytes.TrimSpace(raw), []byte("\n"))
			var e Event
			if err := json.Unmarshal(lines[0], &e); err != nil {
				t.Fatal(err)
			}
			change(&e)
			lines[0] = encodeWebTestEvent(t, e)
			r := Validate(f.Run, bytes.Join(lines, []byte("\n")), inputs)
			if r.Status != "FAIL" {
				t.Fatal("accepted tampered request evidence")
			}
			if len(r.Results) > 0 && r.Results[0].Reason == "serialized record byte count differs" {
				t.Fatal("negative did not reach intended field check")
			}
		})
	}
	t.Run("exact case coverage", func(t *testing.T) {
		f, raw, inputs := webFixture(t)
		f.Run.Attempts = f.Run.Attempts[1:]
		if Validate(f.Run, raw, inputs).Status != "FAIL" {
			t.Fatal("accepted missing case")
		}
	})
}

func encodeWebTestEvent(t *testing.T, e Event) []byte {
	t.Helper()
	for i := 0; i < 8; i++ {
		b, err := json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		v := e.Truncation["record"]
		v.Retained = len(b)
		if !v.Truncated {
			v.Observed = len(b)
		}
		e.Truncation["record"] = v
		n, err := json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		if len(b) == len(n) {
			return n
		}
	}
	t.Fatal("record length failed to stabilize")
	return nil
}
