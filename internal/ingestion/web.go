package ingestion

import (
	"slices"
	"strings"

	"cheesetrap/internal/domain"
)

type webRecord struct {
	Timestamp       string           `json:"timestamp"`
	EventType       string           `json:"event_type"`
	Protocol        string           `json:"protocol"`
	PeerIP          string           `json:"peer_ip"`
	PeerPort        int              `json:"peer_port"`
	DestinationIP   string           `json:"destination_ip"`
	DestinationPort int              `json:"destination_port"`
	Method          *string          `json:"method"`
	URI             *string          `json:"uri"`
	Headers         *[]domain.Header `json:"headers"`
	Body            *string          `json:"body"`
	ParseError      *string          `json:"parse_error"`
	Fields          map[string]struct {
		Status string `json:"status"`
	} `json:"field_completeness"`
	Truncation map[string]domain.Truncation `json:"truncation"`
	Quality    []string                     `json:"quality_flags"`
}

func DecodeWeb(raw []byte, ctx Context) (domain.Event, error) {
	var r webRecord
	if err := readRecord(raw, &r); err != nil {
		return domain.Event{}, err
	}
	if (ctx.Service != "http" && ctx.Service != "https") || r.Protocol != ctx.Service || r.EventType != "web.request" {
		return domain.Event{}, errRecord
	}
	e, err := baseEvent(raw, ctx, "web", r.EventType, r.Timestamp, r.PeerIP, r.PeerPort, r.DestinationIP, r.DestinationPort)
	if err != nil {
		return domain.Event{}, err
	}
	a := &e.Attributes
	a.FieldCompleteness = map[string]string{}
	a.Truncation = map[string]domain.Truncation{}
	// Keep original byte counts, even when engine/fixture redaction changed a
	// retained string's length. These counts never describe the adapter output.
	for field, limit := range map[string]int{"record": RecordLimit, "body": BodyLimit, "uri": URILimit, "headers": HeaderLimit} {
		tr, ok := r.Truncation[field]
		if !ok {
			addFlag(&e, "truncation_metadata_missing")
			continue
		}
		if tr.Limit != limit || tr.Observed < 0 || tr.Retained < 0 || tr.Retained > limit || tr.Observed < tr.Retained || tr.Truncated != (tr.Observed > tr.Retained) {
			addFlag(&e, "truncation_metadata_invalid")
			continue
		}
		a.Truncation[field] = tr
		if tr.Truncated {
			addFlag(&e, field+"_truncated")
		}
	}
	for _, flag := range r.Quality {
		if knownQuality(flag) {
			addFlag(&e, flag)
		} else {
			addFlag(&e, "engine_quality_unknown")
		}
	}
	a.Method = r.Method
	a.URI = r.URI
	a.Headers = r.Headers
	a.Body = r.Body
	a.ParseError = r.ParseError
	for field, present := range map[string]bool{"method": r.Method != nil, "uri": r.URI != nil, "headers": r.Headers != nil, "body": r.Body != nil, "parse_error": r.ParseError != nil} {
		status := "present"
		if !present {
			status = "unavailable"
			addFlag(&e, "required_field_unavailable")
		}
		a.FieldCompleteness[field] = status
		reported, exists := r.Fields[field]
		if !exists {
			addFlag(&e, "field_metadata_missing")
		} else if reported.Status != status {
			addFlag(&e, "field_metadata_inconsistent")
		}
	}
	if a.Method != nil {
		method := *a.Method
		switch method {
		case "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "CONNECT", "TRACE":
		default:
			a.Method = nil
			a.FieldCompleteness["method"] = "unavailable"
			addFlag(&e, "method_unavailable")
			addFlag(&e, "required_field_unavailable")
		}
	}
	if a.ParseError != nil {
		switch *a.ParseError {
		case "", "malformed_http", "uri_limit", "line_limit", "client_disconnect", "headers_limit", "body_limit", "record_limit":
			if *a.ParseError != "" {
				addFlag(&e, *a.ParseError)
			}
		default:
			s := "unknown"
			a.ParseError = &s
			addFlag(&e, "parse_error_unknown")
		}
	}
	if a.URI != nil {
		if len(*a.URI) > URILimit {
			addFlag(&e, "uri_truncated")
			addFlag(&e, "adapter_uri_limit")
		}
		value, changed, withheld := redactURI(*a.URI)
		a.URI = &value
		if changed {
			addFlag(&e, "uri_redacted")
		}
		if withheld {
			addFlag(&e, "uri_redaction_limited")
		}
	}
	contentType, bodyEncodingOK := bodyFormat(r.Headers)
	if a.Headers != nil {
		headers, changed, limited := redactHeaders(*a.Headers)
		a.Headers = &headers
		if changed {
			addFlag(&e, "headers_redacted")
		}
		if limited {
			addFlag(&e, "headers_truncated")
			addFlag(&e, "adapter_headers_limit")
		}
	}
	if a.Body != nil {
		oversized := len(*a.Body) > BodyLimit
		if oversized {
			addFlag(&e, "body_truncated")
			addFlag(&e, "adapter_body_limit")
		}
		partial := a.Truncation["body"].Truncated || slices.Contains(e.QualityFlags, "body_truncated") || oversized || r.ParseError != nil && *r.ParseError != ""
		value, changed, withheld := redactBody(*a.Body, contentType, bodyEncodingOK, partial)
		a.Body = &value
		if changed {
			addFlag(&e, "body_redacted")
		}
		if withheld {
			addFlag(&e, "body_redaction_limited")
		}
	}
	slices.Sort(e.QualityFlags)
	return e, nil
}
func knownQuality(s string) bool {
	switch s {
	case "body_truncated", "uri_truncated", "headers_truncated", "record_truncated", "body_redacted", "headers_redacted", "uri_redacted", "required_field_unavailable", "malformed_http", "uri_limit", "line_limit", "headers_limit", "body_limit", "record_limit", "client_disconnect":
		return true
	}
	return false
}

// A content coding or ambiguous content type cannot be safely interpreted as
// cleartext. Transfer-Encoding is already decoded by the verified engine.
func bodyFormat(headers *[]domain.Header) (string, bool) {
	if headers == nil {
		return "", false
	}
	typ := "text/plain"
	seen := false
	for _, h := range *headers {
		switch strings.ToLower(h.Name) {
		case "content-type":
			if seen {
				return "", false
			}
			seen = true
			typ = h.Value
		case "content-encoding", "content-transfer-encoding":
			if strings.TrimSpace(strings.ToLower(h.Value)) != "identity" {
				return "", false
			}
		}
	}
	return typ, true
}
