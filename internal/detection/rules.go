// Package detection evaluates retained evidence and atomically advances its
// continuous ingestion cursor.
package detection

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"cheesetrap/internal/domain"
)

// Code versions identify matching/eligibility semantics, paths and signatures.
// Threshold settings have their own persisted ingestion-sequence version.
const RuleVersion = "1"
const Window = 10 * time.Minute

// Signature declares precisely which retained fields can support a match.
type Signature struct {
	ID                  string   `json:"id"`
	Version             string   `json:"version"`
	RequiredFields      []string `json:"required_fields"`
	AutoApprovalAllowed bool     `json:"auto_approval_allowed"`
}

func ExploitSignatures() []Signature {
	return []Signature{{ID: "path-traversal-etc-passwd", Version: "1", RequiredFields: []string{"source_ip", "observed_at", "event_type", "attributes.method", "attributes.uri"}, AutoApprovalAllowed: false}}
}
func SuspiciousPaths() []string {
	return []string{"/.env", "/.git/config", "/wp-login.php", "/wp-admin", "/phpmyadmin"}
}

var traversal = regexp.MustCompile(`^/(?:\.\./)+etc/passwd$`)

type Explanation struct {
	SettingsVersion       string    `json:"settings_version,omitempty"`
	RuleConfig            *Config   `json:"rule_config,omitempty"`
	RuleVersion           string    `json:"rule_version"`
	Count                 int       `json:"count"`
	Threshold             int       `json:"threshold"`
	DistinctPathThreshold int       `json:"distinct_path_threshold,omitempty"`
	Paths                 []string  `json:"paths"`
	RequiredFields        []string  `json:"required_fields"`
	ObservedStart         time.Time `json:"observed_start"`
	ObservedEnd           time.Time `json:"observed_end"`
	WindowStart           time.Time `json:"window_start"`
	WindowEnd             time.Time `json:"window_end"`
	HoldReasons           []string  `json:"hold_reasons"`
}
type Result struct {
	SettingsVersion        int64       `json:"settings_version,omitempty"`
	RuleID                 string      `json:"rule_id"`
	RuleVersion            string      `json:"rule_version"`
	SignatureID            string      `json:"signature_id"`
	SignatureVersion       string      `json:"signature_version"`
	AutoApprovalAllowed    bool        `json:"auto_approval_allowed"`
	ProcessingEventID      string      `json:"processing_event_id"`
	ProcessingIngestionSeq uint64      `json:"processing_ingestion_seq"`
	SourceIP               string      `json:"source_ip"`
	EvidenceIDs            []string    `json:"evidence_ids"`
	EvidenceHash           string      `json:"evidence_hash"`
	EvidenceEligible       bool        `json:"evidence_eligible"`
	Explanation            Explanation `json:"explanation"`
}

type rule struct {
	id               string
	threshold, paths int
	required         []string
	signature        Signature
	match            func(domain.Event) (string, bool)
}

func rules(c Config) []rule {
	return []rule{
		{id: "SSH-REPEAT", threshold: c.SSHRepeatThreshold, required: []string{"source_ip", "observed_at", "event_type"}, match: func(e domain.Event) (string, bool) {
			return "", e.Engine == "cowrie" && e.Service == "ssh" && e.EventType == "cowrie.login.failed"
		}},
		{id: "WEB-REPEAT", threshold: c.WebRepeatThreshold, paths: c.WebDistinctPathThreshold, required: []string{"source_ip", "observed_at", "event_type", "attributes.uri"}, match: func(e domain.Event) (string, bool) {
			p, ok := webPath(e)
			return p, ok && slices.Contains(SuspiciousPaths(), p)
		}},
		{id: "WEB-EXPLOIT", threshold: 1, required: ExploitSignatures()[0].RequiredFields, signature: ExploitSignatures()[0], match: func(e domain.Event) (string, bool) {
			p, ok := webPath(e)
			return p, ok && e.Attributes.Method != nil && (*e.Attributes.Method == "GET" || *e.Attributes.Method == "HEAD") && fieldPresent(e, "method") && traversal.MatchString(p)
		}},
	}
}

// triggerNeedsContext reuses the evaluator predicates; nonmatches still go
// through configuration validation, evaluation, and atomic completion.
func triggerNeedsContext(config Config, trigger domain.Event) bool {
	for _, r := range rules(config) {
		if _, matches := r.match(trigger); matches {
			return true
		}
	}
	return false
}

func fieldPresent(e domain.Event, field string) bool {
	value, ok := e.Attributes.FieldCompleteness[field]
	return !ok || value == "present"
}
func webPath(e domain.Event) (string, bool) {
	if e.Engine != "web" || (e.Service != "http" && e.Service != "https") || e.EventType != "web.request" || e.Attributes.URI == nil || !fieldPresent(e, "uri") {
		return "", false
	}
	raw := *e.Attributes.URI
	// Only origin-form URI paths. Never normalize away traversal or interpret
	// encoded bytes, query text, absolute URLs, or attacker-controlled headers.
	if !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") {
		return "", false
	}
	u, err := url.ParseRequestURI(raw)
	if err != nil || u.IsAbs() || u.Host != "" {
		return "", false
	}
	p := u.EscapedPath()
	if strings.ContainsAny(p, "%\\#") {
		return "", false
	}
	return p, true
}
func sourceIP(e domain.Event) (string, bool) {
	ip, err := netip.ParseAddr(e.SourceIP)
	ip = ip.Unmap()
	if err != nil || ip.Zone() != "" || ip.IsUnspecified() || ip.IsMulticast() {
		return "", false
	}
	return ip.Unmap().String(), true
}
func committed(e domain.Event) bool {
	return e.EventID != nil && *e.EventID != "" && e.IngestionSeq != nil && *e.IngestionSeq > 0 && e.IngestedAt != nil
}

// Evaluate uses the trigger and already completed, lower-sequence evidence only.
// The caller must provide the complete +/-10 minute context. There is no hidden
// count limit. Each rule emits at most one result per trigger: the earliest
// qualifying observed-time window containing that trigger. Ingestion time is
// immutable attribution, never the clock used for rule windows.
func Evaluate(trigger domain.Event, processed []domain.Event) ([]Result, error) {
	return EvaluateConfigured(trigger, processed, DefaultConfig(), 0)
}

// EvaluateConfigured uses the configuration selected for this trigger's ingestion
// sequence. Lower-sequence context keeps its evidence role without rerating it.
func EvaluateConfigured(trigger domain.Event, processed []domain.Event, config Config, settingsVersion int64) ([]Result, error) {
	if !config.Valid() || settingsVersion < 0 {
		return nil, errors.New("detection_config_invalid")
	}

	if !committed(trigger) {
		return nil, errors.New("detection requires committed trigger")
	}
	results := []Result{}
	ip, ok := sourceIP(trigger)
	if !ok || trigger.ObservedAt == nil {
		return results, nil
	}
	context := []domain.Event{trigger}
	seen := map[string]bool{*trigger.EventID: true}
	for _, e := range processed {
		if !committed(e) || e.ObservedAt == nil || *e.IngestionSeq >= *trigger.IngestionSeq || seen[*e.EventID] {
			continue
		}
		other, valid := sourceIP(e)
		if !valid || other != ip || e.ObservedAt.Before(trigger.ObservedAt.Add(-Window)) || e.ObservedAt.After(trigger.ObservedAt.Add(Window)) {
			continue
		}
		seen[*e.EventID] = true
		context = append(context, e)
	}
	slices.SortFunc(context, func(a, b domain.Event) int {
		if c := a.ObservedAt.Compare(*b.ObservedAt); c != 0 {
			return c
		}
		if *a.IngestionSeq < *b.IngestionSeq {
			return -1
		}
		if *a.IngestionSeq > *b.IngestionSeq {
			return 1
		}
		return strings.Compare(*a.EventID, *b.EventID)
	})
	for _, r := range rules(config) {
		if _, ok := r.match(trigger); !ok {
			continue
		}
		matched := []domain.Event{}
		paths := []string{}
		for _, e := range context {
			if p, ok := r.match(e); ok {
				matched = append(matched, e)
				paths = append(paths, p)
			}
		}
		// Sliding pointers count every matching event once, then materialize only
		// the first qualifying interval. Sorting dominates O(n log n) work.
		left, right := 0, 0
		counts := map[string]int{}
		for _, candidate := range matched {
			end := *candidate.ObservedAt
			if end.Before(*trigger.ObservedAt) || end.After(trigger.ObservedAt.Add(Window)) {
				continue
			}
			for right < len(matched) && !matched[right].ObservedAt.After(end) {
				if paths[right] != "" {
					counts[paths[right]]++
				}
				right++
			}
			start := end.Add(-Window)
			for left < right && matched[left].ObservedAt.Before(start) {
				p := paths[left]
				if p != "" {
					counts[p]--
					if counts[p] == 0 {
						delete(counts, p)
					}
				}
				left++
			}
			if right-left < r.threshold || len(counts) < r.paths {
				continue
			}
			evidence := matched[left:right]
			ids := make([]string, 0, len(evidence))
			holdSet := map[string]bool{}
			for _, e := range evidence {
				ids = append(ids, *e.EventID)
				for _, h := range holdReasons(e) {
					holdSet[h] = true
				}
			}
			slices.Sort(ids)
			encoded, _ := json.Marshal(ids)
			sum := sha256.Sum256(encoded)
			foundPaths := []string{}
			for p := range counts {
				foundPaths = append(foundPaths, p)
			}
			slices.Sort(foundPaths)
			holds := []string{}
			for h := range holdSet {
				holds = append(holds, h)
			}
			slices.Sort(holds)
			results = append(results, Result{SettingsVersion: settingsVersion, RuleID: r.id, RuleVersion: RuleVersion, SignatureID: r.signature.ID, SignatureVersion: r.signature.Version, AutoApprovalAllowed: r.signature.ID == "" || r.signature.AutoApprovalAllowed, ProcessingEventID: *trigger.EventID, ProcessingIngestionSeq: *trigger.IngestionSeq, SourceIP: ip, EvidenceIDs: ids, EvidenceHash: hex.EncodeToString(sum[:]), EvidenceEligible: len(holds) == 0, Explanation: Explanation{ObservedStart: *evidence[0].ObservedAt, ObservedEnd: *evidence[len(evidence)-1].ObservedAt, RuleVersion: RuleVersion, Count: len(ids), Threshold: r.threshold, DistinctPathThreshold: r.paths, Paths: foundPaths, RequiredFields: slices.Clone(r.required), WindowStart: start, WindowEnd: end, HoldReasons: holds}})
			if settingsVersion > 0 {
				results[len(results)-1].Explanation.SettingsVersion = strconv.FormatInt(settingsVersion, 10)
				copied := config
				results[len(results)-1].Explanation.RuleConfig = &copied
			}
			break
		}
	}
	return results, nil
}
func holdReasons(e domain.Event) []string {
	holds := []string{}
	destination, err := netip.ParseAddr(e.DestinationIP)
	destination = destination.Unmap()
	if err != nil || destination.Zone() != "" || destination.IsUnspecified() || destination.IsMulticast() || e.DestinationPort < 1 || e.DestinationPort > 65535 {
		holds = append(holds, "destination_unavailable")
	}
	if e.IsTest {
		holds = append(holds, "test_evidence")
	}
	if e.ObservedAt != nil && e.IngestedAt != nil && !e.ObservedAt.Before(e.IngestedAt.Add(5*time.Minute)) {
		holds = append(holds, "observed_at_future")
	}
	for field, tr := range e.Attributes.Truncation {
		if tr.Truncated {
			holds = append(holds, field+"_truncated")
		}
	}
	if e.Attributes.ParseError != nil && *e.Attributes.ParseError != "" {
		holds = append(holds, "parse_error")
	}
	for _, flag := range e.QualityFlags {
		// Known redaction retains the particular rule's required fields. Everything
		// else remains visible as a conservative evidence hold, including new flags.
		switch flag {
		case "credentials_redacted", "headers_redacted", "body_redacted", "uri_redacted", "command_redacted":
		default:
			holds = append(holds, flag)
		}
	}
	return holds
}
