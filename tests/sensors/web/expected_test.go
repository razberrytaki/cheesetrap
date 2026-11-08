package web

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http/httputil"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"unicode/utf8"
)

var sensitive = regexp.MustCompile(`(?i)auth|cookie|password|passwd|token|secret|api[-_]?key`)
var digest = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var fullHash = regexp.MustCompile(`^[0-9a-f]{64}$`)

func caseIDs() map[string]bool {
	out := map[string]bool{}
	for _, p := range []string{"http", "https"} {
		for _, s := range []string{"normal-path", "missing-path", "query", "post", "malformed", "oversize-body", "oversize-uri", "oversize-headers", "oversize-record-input", "forged-forwarded", "forged-x-forwarded-for", "forged-x-real-ip", "login-control", "redaction", "chunked", "disconnect", "malformed-secret", "truncated-json", "truncated-form"} {
			out[p+"-"+s] = true
		}
	}
	return out
}
func safeURI(raw string) (string, bool) {
	for _, b := range []byte(raw) {
		if b < 33 || b > 126 {
			return "", false
		}
	}
	if _, e := url.PathUnescape(raw); e != nil {
		return "", false
	}
	path, query, has := strings.Cut(raw, "?")
	if has {
		parts := strings.Split(query, "&")
		for i, p := range parts {
			k, _, _ := strings.Cut(p, "=")
			decoded, _ := url.PathUnescape(k)
			if sensitive.MatchString(decoded) {
				parts[i] = k + "=[REDACTED]"
			}
		}
		raw = path + "?" + strings.Join(parts, "&")
	}
	return raw, len(raw) <= URILimit
}
func contentMatches(id string, raw []byte, e Event) error {
	first, rest, ok := bytes.Cut(raw, []byte("\r\n"))
	if !ok {
		return fmt.Errorf("invalid trusted input line")
	}
	parts := strings.Split(string(first), " ")
	if len(parts) != 3 {
		return fmt.Errorf("unexpected input line")
	}
	if e.Method == nil || *e.Method != parts[0] {
		return fmt.Errorf("method differs from sent input")
	}
	uri := parts[1]
	retained := min(len(uri), URILimit)
	wantURI, valid := safeURI(uri[:retained])
	if !valid || len(uri) > URILimit && strings.Contains(uri, "?") {
		if e.URI != nil {
			return fmt.Errorf("unsafe URI retained")
		}
	} else if e.URI == nil || *e.URI != wantURI {
		return fmt.Errorf("URI/query differs from sent input")
	}
	if e.URI == nil {
		retained = 0
	}
	if e.Truncation["uri"].Retained != retained {
		return fmt.Errorf("URI retained byte count differs")
	}
	if e.Truncation["uri"].Observed != len(uri) {
		return fmt.Errorf("URI observed byte count differs")
	}
	headerBlock, body, ok := bytes.Cut(rest, []byte("\r\n\r\n"))
	if !ok {
		return fmt.Errorf("unexpected trusted input framing")
	}
	partialHeaders := strings.Contains(id, "malformed") || strings.Contains(id, "oversize-uri") || strings.Contains(id, "oversize-headers")
	wantError := ""
	switch {
	case strings.Contains(id, "malformed"):
		wantError = "malformed_http"
	case strings.Contains(id, "oversize-uri"):
		wantError = "uri_limit"
	case strings.Contains(id, "oversize-headers"):
		wantError = "headers_limit"
	case strings.HasSuffix(id, "-disconnect"):
		wantError = "client_disconnect"
	}
	if e.ParseError == nil {
		return fmt.Errorf("parse result unavailable")
	}
	if wantError == "headers_limit" {
		if *e.ParseError != "headers_limit" && *e.ParseError != "line_limit" {
			return fmt.Errorf("header limit not distinguished")
		}
	} else if *e.ParseError != wantError {
		return fmt.Errorf("parse/disconnect classification differs")
	}
	if partialHeaders {
		if e.Truncation["body"].Observed != 0 || e.Truncation["body"].Retained != 0 || e.Truncation["headers"].Retained != 0 {
			return fmt.Errorf("parser-unavailable byte counts were invented")
		}
		if strings.Contains(id, "oversize-headers") && e.Truncation["headers"].Observed <= HeaderLimit {
			return fmt.Errorf("header limit violation not measured")
		}
		if e.Headers != nil || e.Body != nil {
			return fmt.Errorf("parser-unavailable fields were invented")
		}
		return nil
	}
	var headers []Header
	contentType := ""
	chunked := false
	headerBytes := 0
	for _, line := range bytes.Split(headerBlock, []byte("\r\n")) {
		name, value, ok := bytes.Cut(line, []byte(":"))
		if !ok {
			return fmt.Errorf("unexpected malformed trusted header")
		}
		n := strings.ToLower(string(name))
		v := strings.TrimSpace(string(value))
		if n == "content-type" {
			contentType = strings.ToLower(v)
		}
		if n == "transfer-encoding" && v == "chunked" {
			chunked = true
		}
		if sensitive.MatchString(n) {
			v = "[REDACTED]"
		}
		headers = append(headers, Header{Name: n, Value: v})
		headerBytes += len(line) + 2
	}
	if e.Headers == nil || !reflect.DeepEqual(*e.Headers, headers) {
		return fmt.Errorf("headers differ from sent/redacted input")
	}
	if e.Truncation["headers"].Observed != headerBytes || e.Truncation["headers"].Retained != headerBytes {
		return fmt.Errorf("header byte count differs")
	}
	if chunked {
		var err error
		body, err = io.ReadAll(io.LimitReader(httputil.NewChunkedReader(bufio.NewReader(bytes.NewReader(body))), 1<<20))
		if err != nil {
			return err
		}
	}
	observed := len(body)
	body = body[:min(len(body), BodyLimit)]
	text := string(body)
	if strings.Contains(contentType, "json") || strings.Contains(contentType, "form") || strings.Contains(contentType, "multipart") || sensitive.Match(body) {
		if len(body) > 0 {
			text = "[REDACTED structured or sensitive body]"
		}
	} else if !utf8.Valid(body) {
		return fmt.Errorf("unexpected invalid trusted UTF-8")
	}
	if e.Body == nil || *e.Body != text {
		return fmt.Errorf("body differs from bounded/redacted sent input")
	}
	if e.Truncation["body"].Observed != observed || e.Truncation["body"].Retained != len(body) {
		return fmt.Errorf("body byte count differs")
	}
	return nil
}
