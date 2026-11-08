package domain

import (
	"encoding/json"
	"time"
)

// ReportEvidence deliberately excludes credentials, request bodies and headers.
// EventID is copied provenance, not a foreign key to retained ingestion data.
type ReportEvidence struct {
	EventID           string                `json:"event_id"`
	IngestionSeq      int64                 `json:"ingestion_seq"`
	SensorID          string                `json:"sensor_id"`
	Engine            string                `json:"engine"`
	ObservedAt        time.Time             `json:"observed_at"`
	IngestedAt        time.Time             `json:"ingested_at"`
	SourceIP          string                `json:"source_ip"`
	SourcePort        int                   `json:"source_port"`
	DestinationIP     string                `json:"destination_ip"`
	DestinationPort   int                   `json:"destination_port"`
	Service           string                `json:"service"`
	EventType         string                `json:"event_type"`
	Method            string                `json:"method,omitempty"`
	URI               string                `json:"uri,omitempty"`
	Command           string                `json:"command,omitempty"`
	RawHash           string                `json:"raw_hash"`
	QualityFlags      []string              `json:"quality_flags"`
	IsTest            bool                  `json:"is_test"`
	FieldCompleteness map[string]string     `json:"field_completeness,omitempty"`
	Truncation        map[string]Truncation `json:"truncation,omitempty"`
	CollectionGap     json.RawMessage       `json:"collection_gap,omitempty"`
}
type ReportRule struct {
	EvidenceHashScheme string `json:"evidence_hash_scheme,omitempty"`
	SettingsVersion    string `json:"settings_version,omitempty"`
	DetectionID        string `json:"detection_id"`
	RuleID             string `json:"rule_id"`
	RuleVersion        string `json:"rule_version"`
	SignatureID        string `json:"signature_id,omitempty"`
	SignatureVersion   string `json:"signature_version,omitempty"`
	ContextCount       int    `json:"context_count"`
	AttachedCount      int    `json:"attached_count"`
	EvidenceHash       string `json:"evidence_hash"`
	EvidenceEligible   bool   `json:"evidence_eligible"`
	// Legacy signed metadata. It grants no authority and is absent from the API.
	AutoApprovalAllowed bool            `json:"auto_approval_allowed"`
	Explanation         json.RawMessage `json:"explanation"`
}
type ReportSnapshot struct {
	Proof             *ReportProof     `json:"proof,omitempty"`
	Contents          ReportContents   `json:"-"`
	SourceIP          string           `json:"source_ip"`
	WindowID          string           `json:"window_id"`
	WindowStart       time.Time        `json:"window_start"`
	WindowEnd         time.Time        `json:"window_end"`
	ObservedStart     time.Time        `json:"observed_start"`
	ObservedEnd       time.Time        `json:"observed_end"`
	DelayedCollection bool             `json:"delayed_collection"`
	Evidence          []ReportEvidence `json:"evidence"`
	Rules             []ReportRule     `json:"rules"`
	Registry          json.RawMessage  `json:"registry"`
}

// ReportProof is a signed manifest for immutable parts. Existing snapshots
// keep their inline arrays and original content digest.
type ReportProof struct {
	Scheme        string `json:"scheme"`
	EvidenceCount int    `json:"evidence_count"`
	RuleCount     int    `json:"rule_count"`
	EvidenceHash  string `json:"evidence_hash"`
	RulesHash     string `json:"rules_hash"`
}

// ReportContents traverses complete copies with bounded memory. Its database
// lifetime is owned by the caller; it is never serialized into a revision.
type ReportContents interface {
	EachEvidence(func(ReportEvidence) error) error
	EachRule(func(ReportRule) error) error
	Counts() (int, int)
	NullArrays() (bool, bool)
}

func (s ReportSnapshot) EachEvidence(f func(ReportEvidence) error) error {
	if s.Contents != nil {
		return s.Contents.EachEvidence(f)
	}
	for _, e := range s.Evidence {
		if err := f(e); err != nil {
			return err
		}
	}
	return nil
}
func (s ReportSnapshot) EachRule(f func(ReportRule) error) error {
	if s.Contents != nil {
		return s.Contents.EachRule(f)
	}
	for _, r := range s.Rules {
		if err := f(r); err != nil {
			return err
		}
	}
	return nil
}
func (s ReportSnapshot) Counts() (int, int) {
	if s.Proof != nil {
		return s.Proof.EvidenceCount, s.Proof.RuleCount
	}
	if s.Contents != nil {
		return s.Contents.Counts()
	}
	return len(s.Evidence), len(s.Rules)
}

type ReportRevision struct {
	ReportID    string         `json:"report_id"`
	RevisionID  string         `json:"revision_id"`
	Version     int64          `json:"version"`
	Snapshot    ReportSnapshot `json:"snapshot"`
	Recipient   string         `json:"recipient"`
	ReplyTo     string         `json:"reply_to"`
	Subject     string         `json:"subject"`
	Body        string         `json:"body"`
	HoldReasons []string       `json:"hold_reasons"`
	State       string         `json:"state"`
	// Legacy signed metadata. It grants no authority and is absent from the API.
	AutoApprovalAllowed bool   `json:"auto_approval_allowed"`
	BodyEdited          bool   `json:"body_edited"`
	ContentDigest       string `json:"content_digest"`
}
