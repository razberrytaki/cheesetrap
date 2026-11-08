package reporting

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"cheesetrap/internal/domain"
)

func TestRender(t *testing.T) {
	at := time.Date(2026, 10, 20, 1, 2, 3, 0, time.UTC)
	r := domain.ReportRevision{ReportID: "report-id", RevisionID: "revision-id", Version: 1, Recipient: "abuse@example.net", ReplyTo: "operator@example.org", Snapshot: domain.ReportSnapshot{SourceIP: "1.1.1.1", ObservedStart: at, ObservedEnd: at.Add(time.Minute)}}
	r.Snapshot.Rules = []domain.ReportRule{{RuleID: "SSH-REPEAT", RuleVersion: "1", ContextCount: 10}, {RuleID: "WEB-EXPLOIT", RuleVersion: "1", SignatureID: "path-traversal-etc-passwd", SignatureVersion: "1", ContextCount: 1}}
	for _, tc := range []struct {
		name    string
		count   int
		command string
	}{
		{"control_characters", 60, strings.Repeat("猫", 1000) + "\nforged\r\x1b"},
		{"forged_mail_header", 100, strings.Repeat("猫", 4096) + "\r\nBcc: forged@example.net"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := r
			for i := 0; i < tc.count; i++ {
				r.Snapshot.Evidence = append(r.Snapshot.Evidence, domain.ReportEvidence{EventID: "event", ObservedAt: at, SourceIP: "1.1.1.1", DestinationIP: "8.8.8.8", DestinationPort: 2222, Service: "ssh", EventType: "cowrie.login.failed", Command: tc.command})
			}
			subject, body, err := Render(r)
			if err != nil {
				t.Fatal(err)
			}
			for _, s := range []string{"report-id", "2026-10-20T01:02:03Z", "2026-10-20T01:03:03Z", "1.1.1.1", "8.8.8.8:2222", "operator@example.org", fmt.Sprintf("Evidence records: %d", tc.count), "Excerpt shortened for length", "event_id=event", "repeated failed SSH authentication attempts", "path traversal"} {
				if !strings.Contains(body, s) {
					t.Errorf("missing %q", s)
				}
			}
			if strings.ContainsAny(subject, "\r\n") || strings.ContainsAny(body, "\r\x1b") || strings.Contains(body, "\nforged") || strings.Contains(body, "\nBcc:") || !utf8.ValidString(body) {
				t.Fatal("unsafe plaintext")
			}
			if !strings.Contains(body, "Selected event records (UTC):\n") {
				t.Fatal("missing evidence excerpts")
			}
			excerpt := strings.Split(strings.Split(body, "Selected event records (UTC):\n")[1], "\nEnd excerpts.")[0]
			if len(excerpt) > 32*1024 || len(strings.Split(strings.TrimSuffix(excerpt, "\n"), "\n")) > 50 {
				t.Fatal("excerpt limits exceeded")
			}
			_, again, err := Render(r)
			if err != nil || body != again {
				t.Fatal("nondeterministic render")
			}
		})
	}
	t.Run("headers", func(t *testing.T) {
		for _, field := range []string{"recipient", "reply-to"} {
			t.Run(field, func(t *testing.T) {
				mailbox := r.Recipient
				if field == "reply-to" {
					mailbox = r.ReplyTo
				}
				for _, value := range []string{"bad\r\nBcc: x@example.net", "Name <a@example.net>", "a@example.net,b@example.net", mailbox + "\r\nBcc: victim@example.net"} {
					x := r
					if field == "recipient" {
						x.Recipient = value
					} else {
						x.ReplyTo = value
					}
					if _, _, err := Render(x); err == nil {
						t.Fatal("unsafe mailbox accepted")
					}
				}
			})
		}
	})
	t.Run("destination", func(t *testing.T) {
		x := r
		x.Snapshot.Evidence = []domain.ReportEvidence{{DestinationIP: "10.0.0.2", DestinationPort: 2222, Service: "ssh"}}
		_, b, err := Render(x)
		if err != nil || strings.Contains(b, "10.0.0.2") {
			t.Fatal("private destination exposed", err)
		}
	})
}

func TestRenderDigestCanonical(t *testing.T) {
	r := domain.ReportRevision{ReportID: "stable", RevisionID: "random-one", Version: 1, Body: "body", Subject: "subject", Recipient: "abuse@example.net", ReplyTo: "operator@example.org", Snapshot: domain.ReportSnapshot{Registry: []byte(`{"z":9007199254740993,"a":{"b":1,"a":2}}`)}}
	first, err := ContentDigest(r)
	if err != nil {
		t.Fatal(err)
	}
	r.RevisionID = "random-two"
	r.Version = 2
	r.Snapshot.Registry = []byte(`{ "a": {"a":2,"b":1}, "z":9007199254740993 }`)
	second, err := ContentDigest(r)
	if err != nil || first != second {
		t.Fatal("JSON ordering or revision metadata changed content digest", err)
	}
	for _, mutate := range []func(*domain.ReportRevision){func(r *domain.ReportRevision) { r.Body += "x" }, func(r *domain.ReportRevision) { r.Subject += "x" }, func(r *domain.ReportRevision) { r.Recipient = "b@example.net" }, func(r *domain.ReportRevision) { r.ReplyTo = "b@example.org" }, func(r *domain.ReportRevision) { r.Snapshot.ObservedEnd = time.Now() }, func(r *domain.ReportRevision) { r.HoldReasons = []string{"collection_gap"} }} {
		copy := r
		mutate(&copy)
		sum, err := ContentDigest(copy)
		if err != nil || sum == first {
			t.Fatal("changed signed content did not change digest", err)
		}
	}
}

func TestRenderRepeatedRuleSummaries(t *testing.T) {
	r := domain.ReportRevision{ReportID: "stable", Snapshot: domain.ReportSnapshot{SourceIP: "1.1.1.1"}}
	for range 12000 {
		r.Snapshot.Rules = append(r.Snapshot.Rules, domain.ReportRule{RuleID: "SSH-REPEAT", RuleVersion: "1", ContextCount: 10, AttachedCount: 10, Explanation: []byte(`{"threshold":10}`)})
	}
	_, body, err := Render(r)
	if err != nil || len(body) > 10000 || strings.Count(body, "repeated failed SSH authentication attempts") != 1 || strings.Contains(body, "12000") {
		t.Fatal("overlapping detections did not produce bounded rule summary", err, len(body))
	}
}

func TestRenderPartialUTF8Clip(t *testing.T) {
	at := time.Date(2026, 10, 20, 1, 2, 3, 0, time.UTC)
	for _, padding := range []string{"", "a", "aa"} {
		t.Run("alignment_"+padding, func(t *testing.T) {
			r := domain.ReportRevision{ReportID: "report-id", Snapshot: domain.ReportSnapshot{
				SourceIP: "1.1.1.1", ObservedStart: at, ObservedEnd: at,
				Evidence: []domain.ReportEvidence{
					{EventID: "first" + padding, ObservedAt: at, SourceIP: "1.1.1.1", DestinationIP: "8.8.8.8", DestinationPort: 2222, Service: "ssh", Command: strings.Repeat("猫", 20000)},
					{EventID: "second", ObservedAt: time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC), SourceIP: "1.1.1.1", DestinationIP: "9.9.9.9", DestinationPort: 8080, Service: "http"},
				},
			}}
			_, body, err := Render(r)
			if err != nil {
				t.Fatal(err)
			}
			_, excerpt, ok := strings.Cut(body, "Selected event records (UTC):\n")
			if !ok {
				t.Fatal("missing excerpts")
			}
			excerpt, _, ok = strings.Cut(excerpt, "\nEnd excerpts.")
			if !ok {
				t.Fatal("missing excerpt terminator")
			}
			if !utf8.ValidString(excerpt) || len(excerpt) > 32*1024 || strings.Contains(excerpt, "\n") || !strings.HasSuffix(excerpt, "猫") {
				t.Errorf("partial UTF-8 excerpt includes bytes from a subsequent record: bytes=%d", len(excerpt))
			}
			for _, want := range []string{"Evidence records: 2", "Log excerpts included: 1 of 2", "Excerpt shortened for length", "http 9.9.9.9:8080"} {
				if !strings.Contains(body, want) {
					t.Errorf("missing %q", want)
				}
			}
		})
	}
}

// This golden was encoded and signed by the pre-M2-05 types/ContentDigest at
// commit 2ca7563. New absent fields must not alter persisted historical content.
func TestLegacyRevisionDigest(t *testing.T) {
	data, err := os.ReadFile("testdata/legacy-revision-v7.json")
	if err != nil {
		t.Fatal(err)
	}
	var r domain.ReportRevision
	if json.Unmarshal(data, &r) != nil {
		t.Fatal("legacy fixture invalid")
	}
	digest, err := ContentDigest(r)
	if err != nil || digest != r.ContentDigest {
		t.Fatal("pre-M2-05 immutable digest changed", digest, r.ContentDigest, err)
	}
	if len(r.Snapshot.Rules) != 1 || r.Snapshot.Rules[0].SettingsVersion != "" {
		t.Fatal("legacy settings provenance invented")
	}
}

func TestRenderRecipientFacingFacts(t *testing.T) {
	at := time.Date(2026, 10, 20, 1, 2, 3, 0, time.UTC)
	r := domain.ReportRevision{ReportID: "report-id", ReplyTo: "operator@example.org", Snapshot: domain.ReportSnapshot{SourceIP: "1.1.1.1", ObservedStart: at, ObservedEnd: at.Add(time.Minute), Evidence: []domain.ReportEvidence{
		{EventID: "ssh-event", Engine: "cowrie", EventType: "cowrie.login.failed", Service: "ssh", SourceIP: "1.1.1.1", DestinationIP: "8.8.8.8", DestinationPort: 22, ObservedAt: at},
		{EventID: "web-event", Engine: "opencanary", EventType: "web.request", Service: "https", SourceIP: "1.1.1.1", DestinationIP: "8.8.8.8", DestinationPort: 443, ObservedAt: at, Method: "GET", URI: "/../etc/passwd"},
	}, Rules: []domain.ReportRule{
		{RuleID: "SSH-REPEAT", RuleVersion: "1", SettingsVersion: "7", ContextCount: 99},
		{RuleID: "SSH-REPEAT", RuleVersion: "2", SettingsVersion: "8", ContextCount: 100},
		{RuleID: "WEB-EXPLOIT", SignatureID: "path-traversal-etc-passwd", ContextCount: 1},
	}}}
	before, _ := json.Marshal(r)
	_, body, err := Render(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"SSH authentication failed", "HTTP request", "repeated failed SSH authentication attempts", "HTTP requests matching a path traversal pattern", "Evidence records: 2", "Log excerpts included: 2 of 2", "method=GET", "uri=/../etc/passwd", "event_id=ssh-event"} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q", want)
		}
	}
	for _, unwanted := range []string{"cowrie", "opencanary", "SSH-REPEAT", "WEB-EXPLOIT", "settings=v", "threshold:", "matches;", "Total attached evidence", "Collection window", "Delayed collection: no"} {
		if strings.Contains(body, unwanted) {
			t.Errorf("recipient received internal detail %q", unwanted)
		}
	}
	if strings.Count(body, "repeated failed SSH authentication attempts") != 1 {
		t.Error("overlapping rules duplicated the activity summary")
	}
	after, _ := json.Marshal(r)
	if string(before) != string(after) {
		t.Fatal("render altered original evidence or rules")
	}
	r.Snapshot.DelayedCollection = true
	_, body, err = Render(r)
	if err != nil || !strings.Contains(body, "Some records were collected after the activity occurred. The times above are observation times.") {
		t.Fatal("delayed evidence caveat missing", err)
	}
}

func TestRenderUnknownEventDoesNotInventAnAuthenticationFailure(t *testing.T) {
	r := domain.ReportRevision{ReportID: "unknown", Snapshot: domain.ReportSnapshot{SourceIP: "1.1.1.1", Evidence: []domain.ReportEvidence{{EventID: "e", Service: "ssh", EventType: "cowrie.future.event", Command: "echo cowrie"}}}}
	_, body, err := Render(r)
	if err != nil || !strings.Contains(body, "SSH event") || strings.Contains(body, "cowrie.future.event") || strings.Contains(body, "SSH authentication failed") || !strings.Contains(body, "command=echo cowrie") {
		t.Fatal("unknown event mislabeled or evidence text changed", err)
	}
}
