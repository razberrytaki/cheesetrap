package detection

import (
	"cheesetrap/internal/domain"
	"cheesetrap/internal/ingestion"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"testing"
	"time"
)

type fixtureGroup struct {
	Count         int      `json:"count"`
	Start         int      `json:"start_second"`
	Step          int      `json:"step_second"`
	Kind          string   `json:"kind"`
	Paths         []string `json:"paths"`
	Method        string   `json:"method"`
	IP            string   `json:"ip"`
	Flags         []string `json:"flags"`
	Test          bool     `json:"is_test"`
	MissingURI    bool     `json:"missing_uri"`
	MissingMethod bool     `json:"missing_method"`
	Truncated     bool     `json:"truncated"`
	FutureSeconds int      `json:"future_seconds"`
}
type ruleFixture struct {
	Name   string         `json:"name"`
	Groups []fixtureGroup `json:"groups"`
	Rule   string         `json:"rule"`
	Count  int            `json:"evidence_count"`
	Paths  int            `json:"distinct_paths"`
	Hold   string         `json:"hold"`
}

func fixtureEvents(f ruleFixture) []domain.Event {
	base := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	var events []domain.Event
	for _, g := range f.Groups {
		for i := 0; i < g.Count; i++ {
			seq := uint64(len(events) + 1)
			id := fmt.Sprintf("00000000-0000-4000-8000-%012d", seq)
			at := base.Add(time.Duration(g.Start+i*g.Step) * time.Second)
			ingested := base.Add(time.Hour)
			if g.FutureSeconds != 0 {
				ingested = at.Add(-time.Duration(g.FutureSeconds) * time.Second)
			}
			ip := g.IP
			if ip == "" {
				ip = "198.51.100.20"
			}
			e := domain.Event{EventID: &id, IngestionSeq: &seq, ObservedAt: &at, IngestedAt: &ingested, SourceIP: ip, DestinationIP: "192.0.2.1", DestinationPort: 22, Engine: "cowrie", Service: "ssh", EventType: "cowrie.login.failed", QualityFlags: g.Flags, IsTest: g.Test}
			if g.Kind == "web" {
				method := g.Method
				if method == "" {
					method = "GET"
				}
				path := "/"
				if len(g.Paths) > 0 {
					path = g.Paths[i%len(g.Paths)]
				}
				e.Engine = "web"
				e.Service = "http"
				e.EventType = "web.request"
				e.Attributes.Method = &method
				e.Attributes.URI = &path
				e.Attributes.FieldCompleteness = map[string]string{"method": "present", "uri": "present"}
				if g.MissingURI {
					e.Attributes.URI = nil
				}
				if g.MissingMethod {
					e.Attributes.Method = nil
				}
			}
			if g.Kind == "normal" {
				e.EventType = "cowrie.session.connect"
			}
			if g.Truncated {
				e.Attributes.Truncation = map[string]domain.Truncation{"body": {Truncated: true}}
			}
			events = append(events, e)
		}
	}
	return events
}
func TestRulesFixtures(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/rules/cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []ruleFixture
	if err = json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}
	for _, f := range cases {
		t.Run(f.Name, func(t *testing.T) {
			events := fixtureEvents(f)
			got, err := Evaluate(events[len(events)-1], events[:len(events)-1])
			if err != nil {
				t.Fatal(err)
			}
			if f.Rule == "" {
				if len(got) != 0 {
					t.Fatalf("unexpected detection: %+v", got)
				}
				return
			}
			if len(got) != 1 {
				t.Fatalf("detection count=%d; want 1 for %s", len(got), f.Rule)
			}
			r := got[0]
			if r.RuleID != f.Rule || len(r.EvidenceIDs) != f.Count || r.Explanation.Count != f.Count || len(r.Explanation.Paths) != f.Paths {
				t.Fatalf("wrong explanation/evidence: %+v", r)
			}
			if r.RuleVersion == "" || r.EvidenceHash == "" || len(r.Explanation.RequiredFields) == 0 || r.ProcessingEventID != *events[len(events)-1].EventID {
				t.Fatalf("missing provenance: %+v", r)
			}
			if f.Hold != "" {
				if r.EvidenceEligible || !slices.Contains(r.Explanation.HoldReasons, f.Hold) {
					t.Fatalf("missing eligibility hold %q: %+v", f.Hold, r)
				}
			} else if !r.EvidenceEligible {
				t.Fatalf("unexpected evidence hold: %+v", r)
			}
		})
	}
}
func TestRulesDeterministicLateWindow(t *testing.T) {
	events := fixtureEvents(ruleFixture{Groups: []fixtureGroup{{Count: 9, Start: 60, Step: 60}, {Count: 1}}})
	trigger := events[9]
	history := events[:9]
	got, err := Evaluate(trigger, history)
	if err != nil || len(got) != 1 {
		t.Fatalf("late match missing: %v %v", got, err)
	}
	if !got[0].Explanation.WindowEnd.Equal(*events[8].ObservedAt) || !got[0].Explanation.WindowStart.Equal(events[8].ObservedAt.Add(-10*time.Minute)) {
		t.Fatal("late window not anchored at earliest qualifying observed timestamp")
	}
	slices.Reverse(history)
	again, err := Evaluate(trigger, append(history, history[0]))
	if err != nil {
		t.Fatal(err)
	}
	a, _ := json.Marshal(got)
	b, _ := json.Marshal(again)
	if string(a) != string(b) {
		t.Fatal("order or duplicate input changed canonical evidence")
	}
}
func TestRulesNeverUsesHigherSequence(t *testing.T) {
	events := fixtureEvents(ruleFixture{Groups: []fixtureGroup{{Count: 10, Step: 1}}})
	got, err := Evaluate(events[8], events)
	if err != nil || len(got) != 0 {
		t.Fatalf("unprocessed event affected result: %v %v", got, err)
	}
}
func TestRulesTriggerMustBeEvidence(t *testing.T) {
	events := fixtureEvents(ruleFixture{Groups: []fixtureGroup{{Count: 10, Step: 1}, {Count: 1, Kind: "normal"}}})
	got, err := Evaluate(events[10], events[:10])
	if err != nil || len(got) != 0 {
		t.Fatalf("nonmatching trigger re-reported old evidence: %v %v", got, err)
	}
}
func TestRulesRejectsUncommittedTrigger(t *testing.T) {
	if _, err := Evaluate(domain.Event{}, nil); err == nil {
		t.Fatal("uncommitted trigger accepted")
	}
}

func TestRulesDestinationEligibility(t *testing.T) {
	for _, tc := range []struct {
		name, ip string
		port     int
	}{{"missing_address", "", 22}, {"invalid_address", "not-an-ip", 22}, {"zero_port", "192.0.2.1", 0}, {"large_port", "192.0.2.1", 65536}, {"mapped_unspecified", "::ffff:0.0.0.0", 22}, {"mapped_multicast", "::ffff:224.0.0.1", 22}} {
		t.Run(tc.name, func(t *testing.T) {
			events := fixtureEvents(ruleFixture{Groups: []fixtureGroup{{Count: 10}}})
			events[0].DestinationIP = tc.ip
			events[0].DestinationPort = tc.port
			got, err := Evaluate(events[9], events[:9])
			if err != nil || len(got) != 1 {
				t.Fatal("expected candidate")
			}
			if got[0].EvidenceEligible || !slices.Contains(got[0].Explanation.HoldReasons, "destination_unavailable") {
				t.Fatal("invalid required destination evidence remained eligible")
			}
		})
	}
}
func TestRulesActualObservedBounds(t *testing.T) {
	events := fixtureEvents(ruleFixture{Groups: []fixtureGroup{{Count: 10, Start: 60, Step: 30}}})
	got, err := Evaluate(events[9], events[:9])
	if err != nil || len(got) != 1 {
		t.Fatal("expected candidate")
	}
	raw, _ := json.Marshal(got[0].Explanation)
	var fields map[string]json.RawMessage
	json.Unmarshal(raw, &fields)
	for key, want := range map[string]time.Time{"observed_start": *events[0].ObservedAt, "observed_end": *events[9].ObservedAt} {
		var at time.Time
		if json.Unmarshal(fields[key], &at) != nil || !at.Equal(want) {
			t.Errorf("%s did not describe actual evidence range", key)
		}
	}
}
func TestRulesSignatureMetadata(t *testing.T) {
	signatures := ExploitSignatures()
	if len(signatures) != 1 || signatures[0].ID != "path-traversal-etc-passwd" || signatures[0].Version != "1" || signatures[0].AutoApprovalAllowed || !slices.Contains(signatures[0].RequiredFields, "attributes.method") || !slices.Contains(signatures[0].RequiredFields, "attributes.uri") {
		t.Fatal("unsupported signature contract")
	}
	events := fixtureEvents(ruleFixture{Groups: []fixtureGroup{{Count: 1, Kind: "web", Paths: []string{"/../etc/passwd"}}}})
	got, err := Evaluate(events[0], nil)
	if err != nil || len(got) != 1 || got[0].AutoApprovalAllowed || got[0].SignatureID != signatures[0].ID || got[0].SignatureVersion != signatures[0].Version {
		t.Fatal("signature metadata lost from result")
	}
}

func TestRulesRetainedWebEvidence(t *testing.T) {
	for _, tc := range []struct {
		name, uri string
		want      bool
	}{{"literal_traversal", "/../../etc/passwd", true}, {"query_reference_only", "/?file=../../etc/passwd", false}, {"encoded_traversal", "/%2e%2e/etc/passwd", false}, {"benign_path", "/etc/passwd", false}} {
		t.Run(tc.name, func(t *testing.T) {
			at := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
			fields := map[string]map[string]string{}
			for _, f := range []string{"method", "uri", "headers", "body", "parse_error"} {
				fields[f] = map[string]string{"status": "present"}
			}
			truncation := map[string]domain.Truncation{}
			for f, limit := range map[string]int{"record": ingestion.RecordLimit, "body": ingestion.BodyLimit, "uri": ingestion.URILimit, "headers": ingestion.HeaderLimit} {
				truncation[f] = domain.Truncation{Limit: limit}
			}
			raw, err := json.Marshal(map[string]any{"timestamp": at.Format(time.RFC3339), "event_type": "web.request", "protocol": "http", "peer_ip": "198.51.100.20", "peer_port": 12345, "destination_ip": "192.0.2.1", "destination_port": 8080, "method": "GET", "uri": tc.uri, "headers": []domain.Header{}, "body": "", "parse_error": "", "field_completeness": fields, "truncation": truncation, "quality_flags": []string{}})
			if err != nil {
				t.Fatal(err)
			}
			event, err := ingestion.DecodeWeb(raw, ingestion.Context{SensorID: "sensor", Service: "http", ObservedIP: "192.0.2.1", ObservedPort: 8080, PublicIP: "192.0.2.1", PublicPort: 8080, Cursor: domain.SourceCursor{FileGenerationID: "generation"}, ReferenceTime: at})
			if err != nil {
				t.Fatal(err)
			}
			id := "00000000-0000-4000-8000-000000000001"
			seq := uint64(1)
			event.EventID = &id
			event.IngestionSeq = &seq
			event.IngestedAt = &at
			got, err := Evaluate(event, nil)
			if err != nil {
				t.Fatal(err)
			}
			if tc.want {
				if len(got) != 1 || got[0].RuleID != "WEB-EXPLOIT" || !got[0].EvidenceEligible || got[0].AutoApprovalAllowed {
					t.Fatalf("retained adapter fields did not support the declared review-only signature: %+v", got)
				}
			} else if len(got) != 0 {
				t.Fatalf("unsupported retained evidence matched: %+v", got)
			}
		})
	}
}
func TestRulesNoObservedTimeOrSource(t *testing.T) {
	for _, name := range []string{"time", "source"} {
		t.Run(name, func(t *testing.T) {
			events := fixtureEvents(ruleFixture{Groups: []fixtureGroup{{Count: 10}}})
			if name == "time" {
				events[9].ObservedAt = nil
			} else {
				events[9].SourceIP = ""
			}
			got, err := Evaluate(events[9], events[:9])
			if err != nil || len(got) != 0 {
				t.Fatal("missing required evidence matched")
			}
		})
	}
}

func TestRulesInvalidMappedSource(t *testing.T) {
	for _, ip := range []string{"::ffff:0.0.0.0", "::ffff:224.0.0.1"} {
		t.Run(ip, func(t *testing.T) {
			events := fixtureEvents(ruleFixture{Groups: []fixtureGroup{{Count: 10, IP: ip}}})
			got, err := Evaluate(events[9], events[:9])
			if err != nil || len(got) != 0 {
				t.Fatal("invalid mapped source supported detection")
			}
		})
	}
}

// Current rules only combine evidence with the trigger's event type. Keep this
// invariant alongside the SQL optimization so new rules cannot silently lose proof.
func TestContextEventTypeInvariant(t *testing.T) {
	for _, tc := range []struct {
		name, kind string
		paths      []string
		count      int
	}{
		{"SSH-REPEAT", "", nil, 10},
		{"WEB-REPEAT", "web", SuspiciousPaths(), 20},
		{"WEB-EXPLOIT", "web", []string{"/../etc/passwd"}, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			events := fixtureEvents(ruleFixture{Groups: []fixtureGroup{
				{Count: 3, Kind: "normal", Flags: []string{"unrelated_hold"}},
				{Count: tc.count - 1, Kind: tc.kind, Paths: tc.paths, Start: 60, Step: 20, Flags: []string{"collection_gap"}},
				{Count: 1, Kind: tc.kind, Paths: tc.paths},
			}})
			for i := range events {
				if events[i].Service == "http" && i%2 == 0 {
					events[i].Service = "https"
				}
			}
			trigger := events[len(events)-1]
			history := events[:len(events)-1]
			filtered := []domain.Event{}
			for _, e := range history {
				if e.EventType == trigger.EventType {
					filtered = append(filtered, e)
				}
			}
			full, err := EvaluateConfigured(trigger, history, DefaultConfig(), 3)
			if err != nil || len(full) != 1 || full[0].RuleID != tc.name {
				t.Fatalf("fixture did not match %s: %+v %v", tc.name, full, err)
			}
			reduced, err := EvaluateConfigured(trigger, filtered, DefaultConfig(), 3)
			a, _ := json.Marshal(full)
			b, _ := json.Marshal(reduced)
			if err != nil || string(a) != string(b) {
				t.Fatalf("event type filtering changed full result: %s vs %s: %v", a, b, err)
			}
			if !triggerNeedsContext(DefaultConfig(), trigger) {
				t.Fatal("matching trigger skipped context")
			}
		})
	}
}

func TestTriggerNeedsContext(t *testing.T) {
	for _, g := range []fixtureGroup{
		{Count: 1, Kind: "normal"}, {Count: 1, Kind: "web", Paths: []string{"/"}},
		{Count: 1, Kind: "web", Paths: []string{"/.env"}, MissingURI: true},
		{Count: 1, Kind: "web", Paths: []string{"/../etc/passwd"}, MissingMethod: true},
	} {
		e := fixtureEvents(ruleFixture{Groups: []fixtureGroup{g}})[0]
		if triggerNeedsContext(DefaultConfig(), e) {
			t.Fatalf("nonmatching trigger needs context: %+v", g)
		}
	}
}
