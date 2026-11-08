// Package ingestion reads bounded engine records and translates them to
// redacted pre-commit evidence. The adapters are pure; Tailer performs read-only
// file I/O. Neither assigns database commit metadata.
package ingestion

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"cheesetrap/internal/domain"
)

const (
	RecordLimit = 256 * 1024
	BodyLimit   = 16 * 1024
	URILimit    = 8 * 1024
	HeaderLimit = 16 * 1024
)

var (
	errRecord   = errors.New("invalid engine record")
	errLimit    = errors.New("engine record exceeds limit")
	errContext  = errors.New("invalid trusted collector context")
	errEndpoint = errors.New("invalid or unverified engine endpoint")
)

// Context must come from the collector's verified local settings, never from
// record fields. ObservedIP/Port is the inspected socket endpoint and PublicIP/
// Port the operator-verified published endpoint for exactly this sensor/service.
// ReferenceTime only checks the engine clock; it is not a DB collection time.
type Context struct {
	SensorID      string
	Service       string
	ObservedIP    string
	ObservedPort  int
	PublicIP      string
	PublicPort    int
	Cursor        domain.SourceCursor
	IsTest        bool
	ReferenceTime time.Time
	CollectionGap bool
}

type cowrieRecord struct {
	Timestamp       string  `json:"timestamp"`
	EventType       string  `json:"eventid"`
	Session         string  `json:"session"`
	SourceIP        string  `json:"src_ip"`
	SourcePort      int     `json:"src_port"`
	DestinationIP   string  `json:"dst_ip"`
	DestinationPort int     `json:"dst_port"`
	Username        *string `json:"username"`
	Password        *string `json:"password"`
	Input           *string `json:"input"`
}

func DecodeCowrie(raw []byte, ctx Context) (domain.Event, error) {
	var r cowrieRecord
	if err := readRecord(raw, &r); err != nil {
		return domain.Event{}, err
	}
	if ctx.Service != "ssh" {
		return domain.Event{}, errContext
	}
	// eventid describes a type, never an identity suitable for deduplication.
	switch r.EventType {
	case "cowrie.session.connect", "cowrie.session.closed", "cowrie.client.version", "cowrie.client.kex", "cowrie.login.failed", "cowrie.login.success", "cowrie.session.params", "cowrie.command.input", "cowrie.log.closed":
	default:
		return domain.Event{}, errRecord
	}
	e, err := baseEvent(raw, ctx, "cowrie", r.EventType, r.Timestamp, r.SourceIP, r.SourcePort, r.DestinationIP, r.DestinationPort)
	if err != nil {
		return domain.Event{}, err
	}
	if len(r.Session) > 128 || !safeIdentifier(r.Session) {
		return domain.Event{}, errRecord
	}
	e.SessionID = r.Session
	if r.Session == "" {
		addFlag(&e, "session_id_missing")
	}
	e.Attributes.Username = redactCredential(r.Username)
	e.Attributes.Password = redactCredential(r.Password)
	if r.Username != nil || r.Password != nil {
		addFlag(&e, "credentials_redacted")
	}
	if r.Input != nil {
		command := *r.Input
		if len(command) > BodyLimit {
			command = redacted
			addFlag(&e, "command_truncated")
			addFlag(&e, "command_redacted")
		}
		// No shell parser runs here. Quoting and escapes can split option names
		// or values, so withhold the entire command when they are present.
		if strings.ContainsAny(command, "'\"\\") {
			command = redacted
			addFlag(&e, "command_redacted")
			addFlag(&e, "command_redaction_limited")
		}
		if suspiciousText(command) || credentialOption.MatchString(command) {
			command = redacted
			addFlag(&e, "command_redacted")
		}
		e.Attributes.Command = &command
	}
	if r.EventType == "cowrie.command.input" && r.Input == nil {
		addFlag(&e, "command_unavailable")
	}
	if (r.EventType == "cowrie.login.failed" || r.EventType == "cowrie.login.success") && (r.Username == nil || r.Password == nil) {
		addFlag(&e, "credentials_unavailable")
	}
	return e, nil
}

func readRecord(raw []byte, out any) error {
	if len(raw) > RecordLimit {
		return errLimit
	}
	trimmed := strings.TrimSpace(string(raw))
	if len(trimmed) == 0 || trimmed[0] != '{' || !utf8.Valid(raw) || !uniqueJSON(raw) || json.Unmarshal(raw, out) != nil {
		return errRecord
	}
	return nil
}
func address(s string) (netip.Addr, error) {
	ip, err := netip.ParseAddr(s)
	if err != nil || ip.Zone() != "" || ip.IsUnspecified() || ip.IsMulticast() {
		return netip.Addr{}, errEndpoint
	}
	return ip.Unmap(), nil
}
func port(p int) bool { return p > 0 && p <= 65535 }
func safeIdentifier(s string) bool {
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("-_.:", c)) {
			return false
		}
	}
	return true
}
func baseEvent(raw []byte, c Context, engine, kind, stamp, source string, sourcePort int, destination string, destinationPort int) (domain.Event, error) {
	observed, err := address(c.ObservedIP)
	public, ep := address(c.PublicIP)
	if err != nil || ep != nil || !port(c.ObservedPort) || !port(c.PublicPort) || c.SensorID == "" || len(c.SensorID) > 128 || !safeIdentifier(c.SensorID) || c.Cursor.FileGenerationID == "" || len(c.Cursor.FileGenerationID) > 128 || !safeIdentifier(c.Cursor.FileGenerationID) || c.Cursor.ByteOffset < 0 {
		return domain.Event{}, errContext
	}
	sum := sha256.Sum256(raw)
	e := domain.Event{SchemaVersion: 1, SensorID: c.SensorID, Engine: engine, Service: c.Service, EventType: kind, SourceCursor: c.Cursor, RawHash: hex.EncodeToString(sum[:]), QualityFlags: []string{}, IsTest: c.IsTest}
	if stamp == "" {
		addFlag(&e, "observed_at_missing")
	} else if at, err := time.Parse(time.RFC3339Nano, stamp); err != nil {
		addFlag(&e, "observed_at_invalid")
	} else {
		utc := at.UTC()
		e.ObservedAt = &utc
		if !c.ReferenceTime.IsZero() && utc.After(c.ReferenceTime.Add(5*time.Minute)) {
			addFlag(&e, "observed_at_future")
		}
	}
	if c.ReferenceTime.IsZero() {
		addFlag(&e, "time_reference_unavailable")
	}
	if c.CollectionGap {
		addFlag(&e, "collection_gap")
	}
	if source == "" || sourcePort == 0 {
		addFlag(&e, "source_missing")
	}
	if source != "" {
		ip, err := address(source)
		if err != nil {
			return domain.Event{}, errEndpoint
		}
		e.SourceIP = ip.String()
	}
	if sourcePort != 0 {
		if !port(sourcePort) {
			return domain.Event{}, errEndpoint
		}
		e.SourcePort = sourcePort
	}
	if destination == "" || destinationPort == 0 {
		addFlag(&e, "destination_missing")
	} else {
		ip, err := address(destination)
		if err != nil || !port(destinationPort) || ip != observed || destinationPort != c.ObservedPort {
			return domain.Event{}, errEndpoint
		}
		e.DestinationIP = public.String()
		e.DestinationPort = c.PublicPort
	}
	return e, nil
}
func addFlag(e *domain.Event, flag string) {
	if !slices.Contains(e.QualityFlags, flag) {
		e.QualityFlags = append(e.QualityFlags, flag)
	}
}
