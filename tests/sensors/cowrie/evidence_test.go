package cowrie

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"time"
)

type Event struct {
	Timestamp       string `json:"timestamp"`
	EventID         string `json:"eventid"`
	Session         string `json:"session"`
	SourceIP        string `json:"src_ip"`
	SourcePort      int    `json:"src_port,omitempty"`
	DestinationIP   string `json:"dst_ip,omitempty"`
	DestinationPort int    `json:"dst_port,omitempty"`
	Username        string `json:"username,omitempty"`
	Password        string `json:"password,omitempty"`
	Input           string `json:"input,omitempty"`
}
type Attempt struct {
	CaseID      string    `json:"case_id"`
	StartedAt   time.Time `json:"executed_at"`
	EndedAt     time.Time `json:"ended_at"`
	InputFile   string    `json:"input_file"`
	InputSHA256 string    `json:"input_sha256"`
	LocalPort   int       `json:"local_port"`
	Status      string    `json:"status"`
	Reason      string    `json:"reason,omitempty"`
}
type Mapping struct {
	PublicIP        string `json:"public_ip"`
	PublicPort      int    `json:"public_port"`
	HostPort        int    `json:"host_port"`
	ContainerIP     string `json:"container_ip"`
	ContainerPort   int    `json:"container_port"`
	PublishedHostIP string `json:"published_host_ip"`
}
type Run struct {
	RunID         string    `json:"run_id"`
	Image         string    `json:"image_digest"`
	ExpectedIP    string    `json:"expected_ip"`
	AddressFamily string    `json:"address_family"`
	Mapping       Mapping   `json:"destination_mapping"`
	Attempts      []Attempt `json:"attempts"`
}
type Reference struct {
	File    string `json:"file"`
	Line    int    `json:"line"`
	EventID string `json:"event_type"`
}
type FieldEvidence struct {
	Status    string     `json:"status"`
	Source    string     `json:"source"`
	Reference *Reference `json:"reference,omitempty"`
}

type Result struct {
	RunID       string                   `json:"run_id"`
	ExecutedAt  time.Time                `json:"executed_at"`
	Image       string                   `json:"image_digest"`
	InputFile   string                   `json:"input_file"`
	InputSHA256 string                   `json:"input_sha256"`
	ExpectedIP  string                   `json:"expected_ip"`
	Mapping     Mapping                  `json:"destination_mapping"`
	Fields      map[string]FieldEvidence `json:"field_completeness"`
	Truncation  any                      `json:"truncation"`
	CaseID      string                   `json:"case_id"`
	Session     string                   `json:"session_id"`
	PeerIP      string                   `json:"observed_ip"`
	PeerPort    int                      `json:"observed_port"`
	Status      string                   `json:"status"`
	Evidence    []Reference              `json:"evidence_refs"`
}

var digestPattern = regexp.MustCompile(`^cowrie/cowrie@sha256:[0-9a-f]{64}$`)
var hashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Validate requires three executed cases and links every required field to raw
// JSONL lines. Container destinations are checked against inspected Docker
// mapping evidence, never rewritten as if Cowrie directly observed a public IP.
func Validate(run Run, raw []byte) ([]Result, error) {
	if run.RunID == "" || !digestPattern.MatchString(run.Image) || run.AddressFamily != "ipv4" {
		return nil, fmt.Errorf("run: missing identity, pinned image, or supported family")
	}
	if ip, err := netip.ParseAddr(run.ExpectedIP); err != nil || !ip.Is4() {
		return nil, fmt.Errorf("run: invalid expected peer")
	}
	m := run.Mapping
	if ip, err := netip.ParseAddr(m.PublicIP); err != nil || !ip.Is4() {
		return nil, fmt.Errorf("mapping: invalid public destination")
	}
	if ip, err := netip.ParseAddr(m.ContainerIP); err != nil || !ip.Is4() {
		return nil, fmt.Errorf("mapping: invalid container destination")
	}
	if m.PublicPort < 1 || m.PublicPort > 65535 || m.HostPort < 1 || m.HostPort > 65535 || m.ContainerPort != 2222 || m.PublishedHostIP != "0.0.0.0" {
		return nil, fmt.Errorf("mapping: invalid inspected port binding")
	}
	type located struct {
		Event
		line int
		at   time.Time
	}
	var events []located
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 4096), 262144)
	for line := 1; scanner.Scan(); line++ {
		var event Event
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			return nil, fmt.Errorf("raw/cowrie.json:%d: %w", line, err)
		}
		at, err := time.Parse(time.RFC3339Nano, event.Timestamp)
		if err != nil || event.EventID == "" {
			return nil, fmt.Errorf("raw/cowrie.json:%d: invalid timestamp/eventid", line)
		}
		events = append(events, located{event, line, at})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(events) == 0 || len(run.Attempts) != 3 {
		return nil, fmt.Errorf("require raw events and all three input attempts")
	}
	used := map[string]bool{}
	seen := map[string]bool{}
	var results []Result
	for _, attempt := range run.Attempts {
		if attempt.Status != "PASS" || attempt.StartedAt.IsZero() || attempt.EndedAt.Before(attempt.StartedAt) || !hashPattern.MatchString(attempt.InputSHA256) || attempt.InputFile == "" || attempt.LocalPort < 1 || attempt.LocalPort > 65535 {
			return nil, fmt.Errorf("%s: incomplete executed input", attempt.CaseID)
		}
		if seen[attempt.CaseID] {
			return nil, fmt.Errorf("duplicate case %s", attempt.CaseID)
		}
		seen[attempt.CaseID] = true
		required := []string{"cowrie.session.connect"}
		switch attempt.CaseID {
		case "ssh-connect":
		case "ssh-auth-failure":
			required = append(required, "cowrie.login.failed")
		case "ssh-emulated-shell":
			required = append(required, "cowrie.login.success", "cowrie.command.input")
		default:
			return nil, fmt.Errorf("unexpected case %s", attempt.CaseID)
		}
		matched := false
		for _, connection := range events {
			if connection.EventID != "cowrie.session.connect" || connection.Session == "" || used[connection.Session] || connection.SourceIP != run.ExpectedIP || connection.SourcePort < 1 || connection.SourcePort > 65535 || connection.DestinationIP != m.ContainerIP || connection.DestinationPort != m.ContainerPort {
				continue
			}
			// A small, explicit skew bound accommodates independently timed hosts.
			inWindow := func(at time.Time) bool {
				return !at.Before(attempt.StartedAt.Add(-2*time.Second)) && !at.After(attempt.EndedAt.Add(2*time.Second))
			}
			if !inWindow(connection.at) {
				continue
			}
			refs := []Reference{}
			for _, kind := range required {
				for _, event := range events {
					if event.EventID != kind || event.Session != connection.Session || event.SourceIP != run.ExpectedIP || !inWindow(event.at) {
						continue
					}
					if kind == "cowrie.login.failed" && event.Username != "m0-invalid-user" {
						continue
					}
					if kind == "cowrie.login.success" && event.Username != "root" {
						continue
					}
					if kind == "cowrie.command.input" && event.Input != "echo m0-harmless" {
						continue
					}
					refs = append(refs, Reference{File: "raw/cowrie.json", Line: event.line, EventID: kind})
					break
				}
			}
			if len(refs) != len(required) {
				continue
			}
			fields := map[string]FieldEvidence{}
			for name, source := range map[string]string{"timestamp": "timestamp", "peer_ip": "src_ip", "peer_port": "src_port", "session_id": "session", "event_type": "eventid"} {
				reference := refs[0]
				fields[name] = FieldEvidence{Status: "present", Source: source, Reference: &reference}
			}
			connectionRef := refs[0]
			fields["destination"] = FieldEvidence{Status: "present", Source: "dst_ip/dst_port joined to raw/inspect.json HostConfig.PortBindings and NetworkSettings.Networks; public destination declared in run.json", Reference: &connectionRef}
			if len(refs) > 1 {
				reference := refs[len(refs)-1]
				fields["case_event"] = FieldEvidence{Status: "present", Source: "eventid/session plus synthetic username or input", Reference: &reference}
			}
			results = append(results, Result{RunID: run.RunID, ExecutedAt: attempt.StartedAt, Image: run.Image, InputFile: attempt.InputFile, InputSHA256: attempt.InputSHA256, ExpectedIP: run.ExpectedIP, Mapping: run.Mapping, Fields: fields, CaseID: attempt.CaseID, Session: connection.Session, PeerIP: connection.SourceIP, PeerPort: connection.SourcePort, Status: "PASS", Evidence: refs})
			used[connection.Session] = true
			matched = true
			break
		}
		if !matched {
			return nil, fmt.Errorf("%s: missing, invalid, or unlinked required evidence", attempt.CaseID)
		}
	}
	return results, nil
}
