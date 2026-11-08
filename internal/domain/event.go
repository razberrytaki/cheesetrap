// Package domain defines the canonical evidence boundary consumed by later stages.
package domain

import "time"

// Event is pre-commit evidence. EventID, IngestionSeq and IngestedAt stay nil
// until M1 assigns them atomically with the collector checkpoint.
type Event struct {
	EventID         *string      `json:"event_id"`
	IngestionSeq    *uint64      `json:"ingestion_seq"`
	SchemaVersion   int          `json:"schema_version"`
	SensorID        string       `json:"sensor_id"`
	Engine          string       `json:"engine"`
	ObservedAt      *time.Time   `json:"observed_at"`
	IngestedAt      *time.Time   `json:"ingested_at"`
	SourceIP        string       `json:"source_ip"`
	SourcePort      int          `json:"source_port"`
	DestinationIP   string       `json:"destination_ip"`
	DestinationPort int          `json:"destination_port"`
	Service         string       `json:"service"`
	EventType       string       `json:"event_type"`
	SessionID       string       `json:"session_id,omitempty"`
	Attributes      Attributes   `json:"attributes"`
	SourceCursor    SourceCursor `json:"source_cursor"`
	RawHash         string       `json:"raw_hash"`
	QualityFlags    []string     `json:"quality_flags"`
	IsTest          bool         `json:"is_test"`
}

// SourceCursor identifies a record's start, not its content. Neither supported
// engine supplies a stable unique event ID; Cowrie eventid is an event TYPE.
type SourceCursor struct {
	FileGenerationID string `json:"file_generation_id"`
	ByteOffset       int64  `json:"byte_offset"`
}
type Header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}
type Truncation struct {
	Limit     int  `json:"limit"`
	Observed  int  `json:"observed"`
	Retained  int  `json:"retained"`
	Truncated bool `json:"truncated"`
}

// Pointer fields distinguish omitted unavailable evidence from observed emptiness.
// No raw payload or freeform engine message is carried across this boundary.
type Attributes struct {
	Username          *string               `json:"username,omitempty"`
	Password          *string               `json:"password,omitempty"`
	Command           *string               `json:"command,omitempty"`
	Method            *string               `json:"method,omitempty"`
	URI               *string               `json:"uri,omitempty"`
	Headers           *[]Header             `json:"headers,omitempty"`
	Body              *string               `json:"body,omitempty"`
	ParseError        *string               `json:"parse_error,omitempty"`
	FieldCompleteness map[string]string     `json:"field_completeness,omitempty"`
	Truncation        map[string]Truncation `json:"truncation,omitempty"`
}
