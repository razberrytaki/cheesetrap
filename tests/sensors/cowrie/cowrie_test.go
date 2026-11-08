package cowrie

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

func evidenceSample(t *testing.T) (Run, []byte) {
	t.Helper()
	start := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	run := Run{RunID: "unit-example", Image: "cowrie/cowrie@sha256:" + strings.Repeat("a", 64), ExpectedIP: "198.51.100.20", AddressFamily: "ipv4", Mapping: Mapping{PublicIP: "192.0.2.10", PublicPort: 22, HostPort: 2222, ContainerIP: "172.30.0.2", ContainerPort: 2222, PublishedHostIP: "0.0.0.0"}}
	var events []Event
	for i, id := range []string{"ssh-connect", "ssh-auth-failure", "ssh-emulated-shell"} {
		ts := start.Add(time.Duration(i*10) * time.Second)
		run.Attempts = append(run.Attempts, Attempt{CaseID: id, StartedAt: ts, EndedAt: ts.Add(3 * time.Second), InputFile: id + ".json", InputSHA256: strings.Repeat("b", 64), LocalPort: 50000 + i, Status: "PASS"})
		session := []string{"connection", "failure", "shell"}[i]
		events = append(events, Event{Timestamp: ts.Add(time.Second).Format(time.RFC3339Nano), EventID: "cowrie.session.connect", Session: session, SourceIP: run.ExpectedIP, SourcePort: 40000 + i, DestinationIP: run.Mapping.ContainerIP, DestinationPort: 2222})
		if i > 0 {
			event := Event{Timestamp: ts.Add(2 * time.Second).Format(time.RFC3339Nano), Session: session, SourceIP: run.ExpectedIP}
			if i == 1 {
				event.EventID = "cowrie.login.failed"
				event.Username = "m0-invalid-user"
			} else {
				event.EventID = "cowrie.login.success"
				event.Username = "root"
			}
			events = append(events, event)
			if i == 2 {
				event.EventID = "cowrie.command.input"
				event.Input = "echo m0-harmless"
				events = append(events, event)
			}
		}
	}
	var lines []string
	for _, event := range events {
		data, err := json.Marshal(event)
		if err != nil {
			t.Fatal(err)
		}
		lines = append(lines, string(data))
	}
	return run, []byte(strings.Join(lines, "\n") + "\n")
}

func TestCowrieEvidence(t *testing.T) {
	t.Run("links raw sessions and mapped destination", func(t *testing.T) {
		run, raw := evidenceSample(t)
		results, err := Validate(run, raw)
		if err != nil {
			t.Fatal(err)
		}
		if len(results) != 3 {
			t.Fatalf("got %d results, want all three cases", len(results))
		}
		for _, result := range results {
			if len(result.Fields) < 6 {
				t.Fatal("missing field completeness/source references")
			}
			if result.Status != "PASS" || result.PeerIP != run.ExpectedIP || result.PeerPort == 0 || result.Session == "" || len(result.Evidence) == 0 {
				t.Fatalf("incomplete result: %+v", result)
			}
		}
	})
	tests := []struct{ name, old, new string }{
		{"missing timestamp", "2026-10-17T12:00:01Z", ""},
		{"wrong peer", "198.51.100.20", "198.51.100.99"},
		{"wrong destination", "172.30.0.2", "172.30.0.3"},
		{"invalid peer port", `"src_port":40000`, `"src_port":0`},
		{"wrong container port", `"dst_port":2222`, `"dst_port":22`},
		{"broken session", `"session":"failure"`, `"session":"other"`},
		{"missing failure event", "cowrie.login.failed", "cowrie.client.version"},
		{"missing shell auth", "cowrie.login.success", "cowrie.client.version"},
		{"wrong command", "echo m0-harmless", "echo other"},
		{"late command", "2026-10-17T12:00:22Z", "2026-10-18T12:00:22Z"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			run, raw := evidenceSample(t)
			broken := strings.Replace(string(raw), tt.old, tt.new, 1)
			if _, err := Validate(run, []byte(broken)); err == nil {
				t.Fatal("accepted invalid evidence")
			}
		})
	}
	t.Run("missing raw logs", func(t *testing.T) {
		run, _ := evidenceSample(t)
		if _, err := Validate(run, nil); err == nil {
			t.Fatal("accepted absent logs")
		}
	})
	t.Run("unexecuted input", func(t *testing.T) {
		run, raw := evidenceSample(t)
		run.Attempts[0].Status = "BLOCKED"
		if _, err := Validate(run, raw); err == nil {
			t.Fatal("accepted blocked input")
		}
	})
	t.Run("unpinned engine", func(t *testing.T) {
		run, raw := evidenceSample(t)
		run.Image = "cowrie/cowrie:latest"
		if _, err := Validate(run, raw); err == nil {
			t.Fatal("accepted mutable tag")
		}
	})
}

func TestCowrieFixture(t *testing.T) {
	raw, err := os.ReadFile("../../../testdata/engines/cowrie/events.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile("../../../testdata/engines/cowrie/expected.json")
	if err != nil {
		t.Fatal(err)
	}
	var expected Fixture
	if err = json.Unmarshal(data, &expected); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != expected.SHA256 {
		t.Fatal("fixture hash mismatch")
	}
	if expected.Provenance.Kind != "sanitized-real-engine-run" || expected.Provenance.LineCount != bytes.Count(raw, []byte("\n")) || len(expected.Redactions) < 4 || len(expected.Provenance.RawSHA256) != 64 || len(expected.Provenance.RunSHA256) != 64 {
		t.Fatal("missing real-run provenance/redaction metadata")
	}
	got, err := Validate(expected.Run, raw)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, expected.Results) {
		t.Fatalf("fixture/source-field relation differs: got %+v want %+v", got, expected.Results)
	}
	if expected.Run.ExpectedIP != "198.51.100.20" || expected.Run.Mapping.PublicIP != "192.0.2.10" {
		t.Fatal("fixture addresses not sanitized")
	}
}
