package web

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestWebEvidence(t *testing.T) {
	cases, err := LoadCases("../../../testdata/engines/web/cases.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(cases) < 24 {
		t.Fatal("missing HTTP/HTTPS input cases")
	}
	for _, c := range cases {
		t.Run(c.ID, func(t *testing.T) {
			raw, err := c.Bytes("example.invalid")
			if err != nil {
				t.Fatal(err)
			}
			if len(raw) == 0 {
				t.Fatal("empty request")
			}
		})
	}
	t.Run("missing baseline fields are failures with reasons", func(t *testing.T) {
		now := time.Now().UTC()
		a := Attempt{CaseID: "http-normal-path", Protocol: "http", StartedAt: now, EndedAt: now.Add(time.Second), InputSHA256: strings.Repeat("a", 64), InputFile: "inputs/request.bin", LocalPort: 50000, BytesWritten: 50, Status: "SENT"}
		run := Run{RunID: "unit", Variant: "baseline", ImageID: "sha256:" + strings.Repeat("b", 64), ExpectedIP: "198.51.100.20", Attempts: []Attempt{a}}
		report := Validate(run, []byte(`{"logtype":1001,"src_host":"198.51.100.20","src_port":50000,"logdata":{"PATH":"/"}}`+"\n"))
		if report.Status != "FAIL" || len(report.Results) != 1 {
			t.Fatalf("baseline accepted: %+v", report)
		}
		for _, f := range []string{"timestamp", "peer_ip", "peer_port", "destination", "method", "uri", "headers", "body", "parse_error", "truncation"} {
			x, ok := report.Results[0].Fields[f]
			if !ok || x.Status != "missing" || x.Reason == "" {
				t.Fatalf("missing field gap: %s %+v", f, x)
			}
		}
	})
	t.Run("manifest never serializes request secrets", func(t *testing.T) {
		c := Case{ID: "http-redaction", Protocol: "http", Input: Input{Method: "POST", Target: "/?token=secret", Body: "password=secret"}}
		raw, _ := c.Bytes("example.invalid")
		if !bytes.Contains(raw, []byte("secret")) {
			t.Fatal("test must send secret")
		}
		b, _ := json.Marshal(Attempt{CaseID: c.ID, InputSHA256: Hash(raw)})
		if bytes.Contains(b, []byte("secret")) {
			t.Fatal("manifest leaked secret")
		}
	})
}
