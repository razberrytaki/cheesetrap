package ingestion

import (
	"bytes"
	"encoding/json"
	"io"
	"mime"
	"net/url"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"cheesetrap/internal/domain"
)

const redacted = "[REDACTED]"

var credentialAlias = regexp.MustCompile(`(?i)(?:^|[^a-z0-9])(?:pwd|auth|key|session|signature)\s*[:=]`)

// Short credential options accept attached values and shell whitespace. Match
// only an option boundary so ordinary words containing -p or -u stay evidence.
var credentialOption = regexp.MustCompile(`(?:^|[[:space:]])-[pu]`)

func redactCredential(p *string) *string {
	if p == nil {
		return nil
	}
	s := redacted
	return &s
}
func secretKey(key string) bool {
	key = strings.ToLower(key)
	key = strings.Map(func(r rune) rune {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			return r
		}
		return -1
	}, key)
	for _, name := range []string{"password", "passwd", "passphrase", "authorization", "cookie", "token", "secret", "apikey", "credential", "sessionid", "username", "privatekey"} {
		if strings.Contains(key, name) {
			return true
		}
	}
	return key == "pwd" || key == "auth" || key == "key" || key == "session" || key == "signature"
}

// Free text has no reliable credential grammar. Known sensitive labels and
// encoding ambiguity withhold the whole field instead of leaking partial values.
func suspiciousText(s string) bool {
	lower := strings.ToLower(s)
	if credentialAlias.MatchString(s) {
		return true
	}
	for _, word := range []string{"password", "passwd", "passphrase", "authorization", "cookie", "token", "secret", "api_key", "api-key", "apikey", "credential", "private key", "bearer ", "basic ", "username", "session_id", "session-id", "sessionid", "pwd=", "pwd:", "auth=", "auth:", "--user", " -u ", " -p ", "%", "\\x", "\\u"} {
		if strings.Contains(lower, word) {
			return true
		}
	}
	if strings.Contains(s, "://") && strings.Contains(s, "@") {
		return true
	}
	return !utf8.ValidString(s) || strings.ContainsAny(s, "\x00\r")
}

func redactURI(s string) (string, bool, bool) {
	if len(s) > URILimit {
		return redacted, true, true
	}
	u, err := url.ParseRequestURI(s)
	if err != nil {
		return redacted, true, true
	}
	changed := false
	if u.User != nil {
		u.User = nil
		changed = true
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return redacted, true, true
	}
	for key, values := range q {
		if strings.Contains(key, "%") {
			return redacted, true, true
		}
		for i, value := range values {
			if strings.Contains(value, "%") {
				return redacted, true, true
			}
			if secretKey(key) || suspiciousText(value) {
				values[i] = redacted
				changed = true
			}
		}
	}
	if changed {
		u.RawQuery = q.Encode()
	}
	out := u.String()
	if len(out) > URILimit {
		return redacted, true, true
	}
	return out, changed, false
}
func redactHeaders(headers []domain.Header) ([]domain.Header, bool, bool) {
	result := []domain.Header{}
	changed := false
	limited := false
	size := 0
	outputSize := 0
	for _, h := range headers {
		// Account for original evidence bytes even if replacing a long secret would
		// make it small. A complete header is kept or omitted; never split a value.
		n := len(h.Name) + len(h.Value) + 4
		if n > HeaderLimit-size {
			limited = true
			changed = true
			continue
		}
		size += n
		name := strings.ToLower(h.Name)
		valid := name != ""
		for _, c := range name {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", c)) {
				valid = false
			}
		}
		if !valid {
			changed = true
			continue
		}
		value := h.Value
		if secretKey(name) || suspiciousText(value) {
			value = redacted
			changed = true
		}
		retained := len(name) + len(value) + 4
		if retained > HeaderLimit-outputSize {
			limited = true
			changed = true
			continue
		}
		outputSize += retained
		result = append(result, domain.Header{Name: name, Value: value})
	}
	return result, changed, limited
}
func redactBody(body, contentType string, encodingOK, partial bool) (string, bool, bool) {
	if body == "" {
		return "", false, false
	}
	if !encodingOK {
		return redacted, true, true
	}
	typ, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return redacted, true, true
	}
	if charset := strings.ToLower(params["charset"]); charset != "" && charset != "utf-8" && charset != "us-ascii" {
		return redacted, true, true
	}
	switch typ {
	case "application/json":
		if partial || !uniqueJSON([]byte(body)) {
			return redacted, true, true
		}
		var value any
		decoder := json.NewDecoder(strings.NewReader(body))
		decoder.UseNumber()
		if decoder.Decode(&value) != nil {
			return redacted, true, true
		}
		scrubbed, changed, ok := redactJSON(value)
		if !ok {
			return redacted, true, true
		}
		b, err := json.Marshal(scrubbed)
		if err != nil || len(b) > BodyLimit {
			return redacted, true, true
		}
		return string(b), changed, false
	case "application/x-www-form-urlencoded":
		if partial {
			return redacted, true, true
		}
		form, err := url.ParseQuery(body)
		if err != nil {
			return redacted, true, true
		}
		changed := false
		for key, values := range form {
			if strings.Contains(key, "%") {
				return redacted, true, true
			}
			for i, value := range values {
				if strings.Contains(value, "%") {
					return redacted, true, true
				}
				if secretKey(key) || suspiciousText(value) {
					values[i] = redacted
					changed = true
				}
			}
		}
		result := form.Encode()
		if len(result) > BodyLimit {
			return redacted, true, true
		}
		return result, changed, false
	case "text/plain":
		plain := strings.TrimSpace(body)
		if strings.HasPrefix(plain, "{") || strings.HasPrefix(plain, "[") || strings.HasPrefix(plain, "<") || suspiciousText(body) || len(body) > BodyLimit {
			return redacted, true, true
		}
		return body, false, false
	default:
		return redacted, true, true
	}
}
func redactJSON(v any) (any, bool, bool) {
	changed := false
	switch x := v.(type) {
	case map[string]any:
		for key, value := range x {
			if strings.Contains(key, "%") {
				return nil, false, false
			}
			if secretKey(key) {
				x[key] = redacted
				changed = true
				continue
			}
			clean, ch, ok := redactJSON(value)
			if !ok {
				return nil, false, false
			}
			x[key] = clean
			changed = changed || ch
		}
	case []any:
		for i, value := range x {
			clean, ch, ok := redactJSON(value)
			if !ok {
				return nil, false, false
			}
			x[i] = clean
			changed = changed || ch
		}
	case string:
		if suspiciousText(x) {
			return redacted, true, true
		}
	}
	return v, changed, true
}

// Reject duplicate JSON keys, trailing data and excessive nesting before typed
// decoding: Go's last-key-wins behavior would hide contradictory evidence.
func uniqueJSON(raw []byte) bool {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var value func(int) bool
	value = func(depth int) bool {
		if depth > 64 {
			return false
		}
		token, err := d.Token()
		if err != nil {
			return false
		}
		delim, container := token.(json.Delim)
		if !container {
			return true
		}
		switch delim {
		case '{':
			keys := map[string]bool{}
			for d.More() {
				k, err := d.Token()
				key, ok := k.(string)
				key = strings.ToLower(key)
				if err != nil || !ok || keys[key] {
					return false
				}
				keys[key] = true
				if !value(depth + 1) {
					return false
				}
			}
			end, err := d.Token()
			return err == nil && end == json.Delim('}')
		case '[':
			for d.More() {
				if !value(depth + 1) {
					return false
				}
			}
			end, err := d.Token()
			return err == nil && end == json.Delim(']')
		default:
			return false
		}
	}
	if !value(0) {
		return false
	}
	_, err := d.Token()
	return err == io.EOF
}
