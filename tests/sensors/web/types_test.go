package web

import "time"

const BodyLimit = 16 << 10
const URILimit = 8 << 10
const HeaderLimit = 16 << 10
const RecordLimit = 256 << 10

type Attempt struct {
	ContinueVerified bool `json:"continue_verified,omitempty"`

	CaseID         string    `json:"case_id"`
	Protocol       string    `json:"protocol"`
	StartedAt      time.Time `json:"executed_at"`
	EndedAt        time.Time `json:"ended_at"`
	InputFile      string    `json:"input_file"`
	InputSHA256    string    `json:"input_sha256"`
	LocalPort      int       `json:"local_port"`
	BytesWritten   int       `json:"bytes_written"`
	Status         string    `json:"status"`
	ReadOutcome    string    `json:"read_outcome,omitempty"`
	ResponseBytes  int64     `json:"response_bytes"`
	ResponseStatus string    `json:"response_status,omitempty"`
	Reason         string    `json:"reason,omitempty"`
}
type Mapping struct {
	PublicIP      string `json:"public_ip"`
	PublicPort    int    `json:"public_port"`
	HostPort      int    `json:"host_port"`
	ContainerIP   string `json:"container_ip"`
	ContainerPort int    `json:"container_port"`
}
type Run struct {
	RunID                string             `json:"run_id"`
	Variant              string             `json:"variant"`
	ImageID              string             `json:"image_id"`
	Image                string             `json:"image_reference"`
	ExpectedIP           string             `json:"expected_ip"`
	Mappings             map[string]Mapping `json:"destination_mapping"`
	Attempts             []Attempt          `json:"attempts"`
	TLSVerified          bool               `json:"tls_certificate_verified"`
	TLSUntrustedRejected bool               `json:"tls_untrusted_rejected"`
}
type Reference struct {
	File   string `json:"file"`
	Line   int    `json:"line"`
	SHA256 string `json:"sha256"`
}
type Field struct {
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
	Source string `json:"source,omitempty"`
}
type Truncation struct {
	Limit     int  `json:"limit"`
	Observed  int  `json:"observed"`
	Retained  int  `json:"retained"`
	Truncated bool `json:"truncated"`
}
type Header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}
type Event struct {
	Timestamp          string                `json:"timestamp"`
	EventType          string                `json:"event_type"`
	Protocol           string                `json:"protocol"`
	PeerIP             string                `json:"peer_ip"`
	PeerPort           int                   `json:"peer_port"`
	DestinationIP      string                `json:"destination_ip"`
	DestinationPort    int                   `json:"destination_port"`
	Method             *string               `json:"method"`
	URI                *string               `json:"uri"`
	Headers            *[]Header             `json:"headers"`
	Body               *string               `json:"body"`
	ParseError         *string               `json:"parse_error"`
	Fields             map[string]Field      `json:"field_completeness"`
	Truncation         map[string]Truncation `json:"truncation"`
	Quality            []string              `json:"quality_flags"`
	AutoReportEligible bool                  `json:"auto_report_eligible"`
	WireSHA256         string                `json:"wire_sha256"`
	WireBytes          int                   `json:"wire_bytes"`
}
type Result struct {
	CaseID             string                `json:"case_id"`
	Status             string                `json:"status"`
	Reason             string                `json:"reason,omitempty"`
	Attempt            Attempt               `json:"input"`
	Fields             map[string]Field      `json:"field_completeness"`
	Evidence           *Reference            `json:"evidence,omitempty"`
	PeerIP             string                `json:"observed_ip,omitempty"`
	PeerPort           int                   `json:"observed_port,omitempty"`
	Mapping            Mapping               `json:"destination_mapping"`
	Truncation         map[string]Truncation `json:"truncation"`
	AutoReportEligible bool                  `json:"auto_report_eligible"`
	Quality            []string              `json:"quality_flags"`
}
type Report struct {
	Status  string   `json:"status"`
	Reason  string   `json:"reason,omitempty"`
	RunID   string   `json:"run_id"`
	Variant string   `json:"variant"`
	ImageID string   `json:"image_id"`
	Results []Result `json:"results"`
}
