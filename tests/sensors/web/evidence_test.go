package web

import (
	"bufio"
	"bytes"
	"encoding/json"
	"net/netip"
	"strings"
	"time"
)

var required = []string{"timestamp", "peer_ip", "peer_port", "destination", "method", "uri", "headers", "body", "parse_error", "truncation"}

func Validate(run Run, raw []byte, inputMaps ...map[string][]byte) Report {
	inputs := map[string][]byte{}
	if len(inputMaps) > 0 {
		inputs = inputMaps[0]
	}
	expectedIDs := caseIDs()
	seenIDs := map[string]bool{}
	report := Report{Status: "FAIL", RunID: run.RunID, Variant: run.Variant, ImageID: run.ImageID}
	type located struct {
		event Event
		line  int
		hash  string
		size  int
	}
	var events []located
	scan := bufio.NewScanner(bytes.NewReader(raw))
	scan.Buffer(make([]byte, 4096), RecordLimit+1)
	for n := 1; scan.Scan(); n++ {
		var e Event
		if json.Unmarshal(scan.Bytes(), &e) != nil {
			report.Reason = "invalid JSONL"
			return report
		}
		if e.EventType == "web.request" {
			events = append(events, located{e, n, Hash(scan.Bytes()), len(scan.Bytes())})
		}
	}
	if scan.Err() != nil {
		report.Reason = "record exceeds 256 KiB"
		return report
	}
	used := map[int]bool{}
	for _, a := range run.Attempts {
		validAttempt := expectedIDs[a.CaseID] && strings.HasPrefix(a.CaseID, a.Protocol+"-") && !seenIDs[a.CaseID] && a.Status == "SENT" && !a.StartedAt.IsZero() && !a.EndedAt.Before(a.StartedAt) && a.LocalPort > 0 && a.LocalPort < 65536 && fullHash.MatchString(a.InputSHA256)
		if strings.HasSuffix(a.CaseID, "-disconnect") && !a.ContinueVerified {
			validAttempt = false
		}
		seenIDs[a.CaseID] = true
		input := inputs[a.CaseID]
		validAttempt = validAttempt && len(input) == a.BytesWritten && Hash(input) == a.InputSHA256
		r := Result{CaseID: a.CaseID, Status: "FAIL", Attempt: a, Fields: map[string]Field{}, Mapping: run.Mappings[a.Protocol]}
		for _, f := range required {
			r.Fields[f] = Field{Status: "missing", Reason: "no linked request-boundary event in actual engine log"}
		}
		for _, l := range events {
			e := l.event
			at, err := time.Parse(time.RFC3339Nano, e.Timestamp)
			if used[l.line] || err != nil || e.Protocol != a.Protocol || at.Before(a.StartedAt.Add(-2*time.Second)) || at.After(a.EndedAt.Add(2*time.Second)) {
				continue
			}
			if !validAttempt || e.WireBytes < 1 || e.WireBytes > len(input) || Hash(input[:e.WireBytes]) != e.WireSHA256 {
				continue
			}
			used[l.line] = true
			r.Evidence = &Reference{File: "raw/events.jsonl", Line: l.line, SHA256: l.hash}
			r.PeerIP = e.PeerIP
			r.PeerPort = e.PeerPort
			r.Truncation = e.Truncation
			r.Quality = e.Quality
			r.AutoReportEligible = e.AutoReportEligible
			r.Fields = e.Fields
			if f, ok := r.Fields["destination"]; ok && f.Status == "present" {
				f.Source = "destination_ip/destination_port joined to raw/inspect.json port binding and network"
				r.Fields["destination"] = f
			}
			r.Status = "PASS"
			for _, field := range []string{"timestamp", "peer_ip", "peer_port", "destination", "parse_error", "truncation"} {
				if e.Fields[field].Status != "present" {
					r.Status = "FAIL"
					r.Reason = "required transport/parser metadata unavailable: " + field
				}
			}
			if !strings.Contains(a.CaseID, "malformed") && !strings.Contains(a.CaseID, "oversize-uri") && !strings.Contains(a.CaseID, "oversize-headers") && e.WireBytes != len(input) {
				r.Status = "FAIL"
				r.Reason = "incomplete received-byte provenance"
			}
			for _, f := range required {
				x, ok := r.Fields[f]
				if !ok || (x.Status != "present" && x.Status != "unavailable") || x.Status == "unavailable" && (x.Reason == "" || e.AutoReportEligible || len(e.Quality) == 0) {
					r.Status = "FAIL"
					r.Reason = "missing or unjustified unavailable field: " + f
				}
			}
			m := run.Mappings[a.Protocol]
			if e.PeerIP != run.ExpectedIP || e.PeerPort < 1 || e.PeerPort > 65535 || e.DestinationIP != m.ContainerIP || e.DestinationPort != m.ContainerPort {
				r.Status = "FAIL"
				r.Reason = "transport peer or inspected destination mismatch"
			}
			if e.WireBytes < 1 || len(e.WireSHA256) != 64 {
				r.Status = "FAIL"
				r.Reason = "missing received-byte provenance"
			}
			for name, limit := range map[string]int{"body": BodyLimit, "uri": URILimit, "headers": HeaderLimit, "record": RecordLimit} {
				v, ok := e.Truncation[name]
				if !ok || v.Limit != limit || v.Retained > limit || v.Observed < v.Retained || v.Truncated != (v.Observed > v.Retained) {
					r.Status = "FAIL"
					r.Reason = "invalid bound: " + name
				}
			}
			for field, present := range map[string]bool{"method": e.Method != nil, "uri": e.URI != nil, "headers": e.Headers != nil, "body": e.Body != nil, "parse_error": e.ParseError != nil} {
				if (e.Fields[field].Status == "present") != present {
					r.Status = "FAIL"
					r.Reason = "field completeness contradicts actual value: " + field
				}
			}
			if e.Truncation["record"].Retained != l.size {
				r.Status = "FAIL"
				r.Reason = "serialized record byte count differs"
			}
			if err := contentMatches(a.CaseID, input, e); err != nil {
				r.Status = "FAIL"
				r.Reason = err.Error()
			}
			for field, v := range e.Truncation {
				if v.Truncated && !contains(e.Quality, field+"_truncated") && e.Fields[field].Status != "unavailable" {
					r.Status = "FAIL"
					r.Reason = "truncation quality flag missing: " + field
				}
			}
			if e.AutoReportEligible {
				r.Status = "FAIL"
				r.Reason = "synthetic validation inputs must not trigger automatic reports"
			}
			break
		}
		if r.Evidence == nil {
			r.Reason = run.Variant + " engine did not emit a linked complete request-boundary evidence record"
		}
		report.Results = append(report.Results, r)
	}
	if len(report.Results) == 0 {
		report.Reason = "no executed cases"
		return report
	}
	report.Status = "PASS"
	for _, r := range report.Results {
		if r.Status != "PASS" {
			report.Status = "FAIL"
			report.Reason = "one or more cases lack required evidence"
		}
	}
	if !digest.MatchString(run.ImageID) || len(run.Attempts) != len(expectedIDs) || len(seenIDs) != len(expectedIDs) {
		report.Status = "FAIL"
		report.Reason = "missing immutable image ID or exact case coverage"
	}
	if ip, err := netip.ParseAddr(run.ExpectedIP); err != nil || !ip.Is4() {
		report.Status = "FAIL"
		report.Reason = "invalid expected peer"
	}
	if run.RunID == "" || (run.Variant != "baseline" && run.Variant != "patched") {
		report.Status = "FAIL"
		report.Reason = "invalid run identity/variant"
	}
	if run.Variant == "patched" && (len(events) != len(run.Attempts) || len(used) != len(events)) {
		report.Status = "FAIL"
		report.Reason = "request events are missing, duplicated, or unlinked"
	}
	for _, p := range []string{"http", "https"} {
		m := run.Mappings[p]
		expectedPort := 8080
		if p == "https" {
			expectedPort = 8443
		}
		pub, ep := netip.ParseAddr(m.PublicIP)
		container, ec := netip.ParseAddr(m.ContainerIP)
		if ep != nil || ec != nil || !pub.Is4() || !container.Is4() || m.ContainerPort != expectedPort || m.PublicPort < 1 || m.PublicPort > 65535 || m.HostPort < 1 || m.HostPort > 65535 {
			report.Status = "FAIL"
			report.Reason = "invalid public-to-container destination mapping"
		}
	}
	if run.Variant == "baseline" {
		annotateBaseline(&report, run, raw)
	}
	return report
}
func contains(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}
