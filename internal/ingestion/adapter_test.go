package ingestion

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"cheesetrap/internal/domain"
)

type fixtureManifest struct {
	SchemaVersion int               `json:"schema_version"`
	Limits        map[string]int    `json:"limits"`
	CommonFields  map[string]string `json:"common_fields"`
	Engines       []struct {
		Engine         string `json:"engine"`
		Fixture        string `json:"fixture"`
		Expected       string `json:"expected"`
		FixtureSHA256  string `json:"fixture_sha256"`
		OriginalSHA256 string `json:"original_raw_sha256"`
		RowCount       int    `json:"row_count"`
		Mappings       []struct {
			Service      string `json:"service"`
			ObservedIP   string `json:"observed_ip"`
			ObservedPort int    `json:"observed_port"`
			PublicIP     string `json:"public_ip"`
			PublicPort   int    `json:"public_port"`
		} `json:"destinations"`
		Rows []struct {
			Line    int      `json:"line"`
			Offset  int64    `json:"byte_offset"`
			Hash    string   `json:"raw_hash"`
			Quality []string `json:"engine_quality_flags"`
		} `json:"rows"`
	} `json:"engines"`
}

func digest(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
func ptr(s string) *string   { return &s }
func contextFor(service string) Context {
	c := Context{SensorID: "sensor-verified", Service: service, ObservedIP: "172.30.0.2", PublicIP: "192.0.2.10", Cursor: domain.SourceCursor{FileGenerationID: "generation-1"}, ReferenceTime: time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC)}
	switch service {
	case "ssh":
		c.ObservedPort = 2222
		c.PublicPort = 2222
	case "http":
		c.ObservedPort = 8080
		c.PublicPort = 18080
	case "https":
		c.ObservedPort = 8443
		c.PublicPort = 18443
	}
	return c
}
func baseCowrie() map[string]any {
	return map[string]any{"timestamp": "2026-10-17T23:00:00+09:00", "eventid": "cowrie.login.failed", "session": "session-001", "src_ip": "198.51.100.20", "src_port": 12345, "dst_ip": "172.30.0.2", "dst_port": 2222, "username": "root", "password": "cowrie-secret"}
}
func baseWeb() map[string]any {
	return map[string]any{"timestamp": "2026-10-17T23:00:00+09:00", "event_type": "web.request", "protocol": "http", "peer_ip": "198.51.100.20", "peer_port": 12345, "destination_ip": "172.30.0.2", "destination_port": 8080, "method": "POST", "uri": "/search?q=hello&tag=one&tag=two", "headers": []domain.Header{{Name: "content-type", Value: "text/plain"}, {Name: "x-forwarded-for", Value: "203.0.113.99"}}, "body": "hello", "parse_error": "", "field_completeness": map[string]any{}, "truncation": map[string]any{}, "quality_flags": []string{}}
}
func encoded(t *testing.T, v any) []byte {
	t.Helper()
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func decode(t *testing.T, engine string, record map[string]any, c Context) domain.Event {
	t.Helper()
	fn := DecodeWeb
	if engine == "cowrie" {
		fn = DecodeCowrie
	}
	e, err := fn(encoded(t, record), c)
	if err != nil {
		t.Fatal(err)
	}
	return e
}
func flagged(t *testing.T, e domain.Event, want string) {
	t.Helper()
	if !slices.Contains(e.QualityFlags, want) {
		t.Errorf("missing quality %s; got %v", want, e.QualityFlags)
	}
}
func absent(t *testing.T, e domain.Event, values ...string) {
	t.Helper()
	b := encoded(t, e)
	for _, v := range values {
		if bytes.Contains(b, []byte(v)) {
			t.Errorf("serialized common event leaks secret %q", v)
		}
	}
}

func TestDecodeEngineEvidence(t *testing.T) {
	t.Run("real fixtures and manifest", func(t *testing.T) {
		b, err := os.ReadFile("../../testdata/engines/manifest.json")
		if err != nil {
			t.Fatal(err)
		}
		var m fixtureManifest
		if err = json.Unmarshal(b, &m); err != nil {
			t.Fatal(err)
		}
		if m.SchemaVersion != 1 || len(m.CommonFields) != 19 || !reflect.DeepEqual(m.Limits, map[string]int{"record": RecordLimit, "body": BodyLimit, "uri": URILimit, "headers": HeaderLimit}) {
			t.Fatal("manifest contract is incomplete")
		}
		typ := reflect.TypeOf(domain.Event{})
		for i := 0; i < typ.NumField(); i++ {
			key := strings.Split(typ.Field(i).Tag.Get("json"), ",")[0]
			if v := m.CommonFields[key]; v == "" || v == "TODO" {
				t.Fatalf("missing manifest mapping for %s", key)
			}
		}
		count := 0
		for _, f := range m.Engines {
			raw, err := os.ReadFile("../../testdata/engines/" + f.Fixture)
			if err != nil {
				t.Fatal(err)
			}
			if digest(raw) != f.FixtureSHA256 || f.OriginalSHA256 == f.FixtureSHA256 || len(f.OriginalSHA256) != 64 {
				t.Fatal("fixture/original provenance hashes differ from contract")
			}
			expected, err := os.ReadFile("../../testdata/engines/" + f.Expected)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Contains(expected, []byte(f.FixtureSHA256)) || !bytes.Contains(expected, []byte(f.OriginalSHA256)) {
				t.Fatal("manifest is detached from existing provenance")
			}
			lines := bytes.Split(bytes.TrimSuffix(raw, []byte("\n")), []byte("\n"))
			if len(lines) != f.RowCount || len(f.Rows) != f.RowCount {
				t.Fatal("row count mismatch")
			}
			var offset int64
			for i, line := range lines {
				var r map[string]any
				if err := json.Unmarshal(line, &r); err != nil {
					t.Fatal(err)
				}
				service := "ssh"
				if f.Engine == "web" {
					service = r["protocol"].(string)
				}
				c := contextFor(service)
				c.IsTest = true
				c.Cursor.ByteOffset = offset
				match := false
				for _, d := range f.Mappings {
					if d.Service == service {
						match = d.ObservedIP == c.ObservedIP && d.ObservedPort == c.ObservedPort && d.PublicIP == c.PublicIP && d.PublicPort == c.PublicPort
					}
				}
				if !match {
					t.Fatal("fixture mapping missing")
				}
				fn := DecodeWeb
				if f.Engine == "cowrie" {
					fn = DecodeCowrie
				}
				e, err := fn(line, c)
				if err != nil {
					t.Fatalf("%s line %d: %v", f.Engine, i+1, err)
				}
				row := f.Rows[i]
				if row.Line != i+1 || row.Offset != offset || row.Hash != digest(line) || e.RawHash != row.Hash || e.SourceCursor != c.Cursor {
					t.Fatal("record hash/position mismatch")
				}
				if e.EventID != nil || e.IngestionSeq != nil || e.IngestedAt != nil || e.SchemaVersion != 1 || e.Engine != f.Engine || e.SensorID != c.SensorID || !e.IsTest {
					t.Fatal("precommit/trust contract broken")
				}
				sourcePortField := "peer_port"
				typeField := "event_type"
				if f.Engine == "cowrie" {
					sourcePortField = "src_port"
					typeField = "eventid"
				}
				if e.EventType != r[typeField] || e.SourcePort != int(r[sourcePortField].(float64)) {
					t.Fatal("engine type or socket port changed")
				}
				if e.SourceIP != "198.51.100.20" || e.SourcePort < 1 || e.DestinationIP != c.PublicIP || e.DestinationPort != c.PublicPort || e.Service != service {
					t.Fatal("socket/mapped endpoints lost")
				}
				at, _ := time.Parse(time.RFC3339Nano, r["timestamp"].(string))
				if e.ObservedAt == nil || !e.ObservedAt.Equal(at) || e.ObservedAt.Location() != time.UTC {
					t.Fatal("observation time lost")
				}
				for _, q := range []string{"field_metadata_missing", "field_metadata_inconsistent", "truncation_metadata_missing", "truncation_metadata_invalid", "parse_error_unknown", "engine_quality_unknown"} {
					if slices.Contains(e.QualityFlags, q) {
						t.Fatalf("real fixture unexpectedly violates engine contract: %s", q)
					}
				}
				for _, q := range row.Quality {
					flagged(t, e, q)
				}
				if f.Engine == "web" {
					for _, key := range []string{"method", "uri", "headers", "body", "parse_error"} {
						if r[key] == nil && e.Attributes.FieldCompleteness[key] != "unavailable" {
							t.Errorf("%s falsely complete", key)
						}
					}
					var original struct {
						Truncation map[string]domain.Truncation `json:"truncation"`
					}
					json.Unmarshal(line, &original)
					for key, v := range original.Truncation {
						if e.Attributes.Truncation[key] != v {
							t.Errorf("engine truncation lost: %s line %d", key, i+1)
						}
						if v.Truncated {
							flagged(t, e, key+"_truncated")
						}
					}
				}
				offset += int64(len(line) + 1)
				count++
			}
		}
		if count != 56 {
			t.Fatalf("decoded %d rows, want 56", count)
		}
	})
	t.Run("trust and timestamps", func(t *testing.T) {
		for _, engine := range []string{"cowrie", "web"} {
			r := baseWeb()
			c := contextFor("http")
			if engine == "cowrie" {
				r = baseCowrie()
				c = contextFor("ssh")
			}
			for k, v := range map[string]any{"is_test": true, "sensor_id": "forged", "source_ip": "203.0.113.99", "source_port": 1, "engine": "forged", "event_id": "forged", "ingestion_seq": 99, "ingested_at": "2000-01-01T00:00:00Z", "source_cursor": map[string]any{"byte_offset": 99}, "raw_hash": "forged"} {
				r[k] = v
			}
			e := decode(t, engine, r, c)
			if e.IsTest || e.SourceIP != "198.51.100.20" || e.SourcePort != 12345 || e.SensorID != c.SensorID || e.SourceCursor != c.Cursor || e.EventID != nil || e.IngestionSeq != nil || e.IngestedAt != nil {
				t.Fatal("untrusted field assigned trusted state")
			}
			if e.ObservedAt == nil || e.ObservedAt.Format(time.RFC3339) != "2026-10-17T14:00:00Z" {
				t.Fatal("UTC normalization failed")
			}
			c.IsTest = true
			c.CollectionGap = true
			e = decode(t, engine, r, c)
			if !e.IsTest {
				t.Fatal("local test context lost")
			}
			flagged(t, e, "collection_gap")
			r["timestamp"] = "2026-10-18T00:05:01Z"
			e = decode(t, engine, r, c)
			flagged(t, e, "observed_at_future")
			delete(r, "timestamp")
			e = decode(t, engine, r, c)
			if e.ObservedAt != nil {
				t.Fatal("invented timestamp")
			}
			flagged(t, e, "observed_at_missing")
		}
	})
	t.Run("address normalization and destination match", func(t *testing.T) {
		for _, ip := range []string{"::ffff:198.51.100.20", "2001:0db8:0:0::20"} {
			r := baseWeb()
			r["peer_ip"] = ip
			r["destination_ip"] = "::ffff:172.30.0.2"
			c := contextFor("http")
			c.PublicIP = "::ffff:192.0.2.10"
			e := decode(t, "web", r, c)
			want := "198.51.100.20"
			if strings.HasPrefix(ip, "2001") {
				want = "2001:db8::20"
			}
			if e.SourceIP != want || e.DestinationIP != "192.0.2.10" {
				t.Fatal("noncanonical IP")
			}
		}
		for _, patch := range []map[string]any{{"peer_ip": "bad-secret"}, {"peer_port": 65536}, {"destination_ip": "203.0.113.66"}, {"destination_port": 18443}, {"protocol": "https"}} {
			r := baseWeb()
			for k, v := range patch {
				r[k] = v
			}
			if _, err := DecodeWeb(encoded(t, r), contextFor("http")); err == nil {
				t.Fatal("accepted invalid/mismatched endpoint")
			}
		}
		c := contextFor("http")
		c.Cursor.FileGenerationID = ""
		if _, err := DecodeWeb(encoded(t, baseWeb()), c); err == nil {
			t.Fatal("cursor must be local and assigned")
		}
	})
	t.Run("missing versus empty", func(t *testing.T) {
		r := baseWeb()
		r["body"] = ""
		r["headers"] = []domain.Header{}
		e := decode(t, "web", r, contextFor("http"))
		if e.Attributes.Body == nil || *e.Attributes.Body != "" || e.Attributes.Headers == nil {
			t.Fatal("observed emptiness lost")
		}
		for _, k := range []string{"timestamp", "peer_ip", "peer_port", "destination_ip", "destination_port", "method", "uri", "headers", "body", "parse_error"} {
			delete(r, k)
		}
		e = decode(t, "web", r, contextFor("http"))
		if e.SourceIP != "" || e.SourcePort != 0 || e.DestinationIP != "" || e.DestinationPort != 0 || e.ObservedAt != nil || e.Attributes.Body != nil {
			t.Fatal("missing evidence invented")
		}
		for _, q := range []string{"observed_at_missing", "source_missing", "destination_missing", "required_field_unavailable"} {
			flagged(t, e, q)
		}
	})
	t.Run("safe record rejection and independent identical records", func(t *testing.T) {
		for _, raw := range [][]byte{[]byte(`{"password":"do-not-echo"`), []byte(`null`), []byte(`[]`), []byte(strings.Repeat("x", RecordLimit+1)), []byte(`{"timestamp":1}`)} {
			for _, adapter := range []struct {
				fn      func([]byte, Context) (domain.Event, error)
				service string
			}{{DecodeCowrie, "ssh"}, {DecodeWeb, "http"}} {
				_, err := adapter.fn(raw, contextFor(adapter.service))
				if err == nil || strings.Contains(err.Error(), "do-not-echo") {
					t.Fatal("unsafe rejection")
				}
			}
		}
		r := baseCowrie()
		c := contextFor("ssh")
		e1 := decode(t, "cowrie", r, c)
		c.Cursor.ByteOffset = 100
		e2 := decode(t, "cowrie", r, c)
		if e1.RawHash != e2.RawHash || e1.SourceCursor == e2.SourceCursor {
			t.Fatal("content hash is not a deduplication identity")
		}
	})
	t.Run("limits and quality", func(t *testing.T) {
		r := baseWeb()
		r["uri"] = "/" + strings.Repeat("a", URILimit)
		r["body"] = strings.Repeat("a", BodyLimit+1)
		r["headers"] = []domain.Header{{Name: "x-probe", Value: strings.Repeat("a", HeaderLimit+1)}}
		r["parse_error"] = "secret-error-text"
		r["quality_flags"] = []string{"secret-quality-text"}
		e := decode(t, "web", r, contextFor("http"))
		absent(t, e, "secret-error-text", "secret-quality-text")
		for _, q := range []string{"uri_truncated", "body_truncated", "headers_truncated", "parse_error_unknown", "engine_quality_unknown"} {
			flagged(t, e, q)
		}
		if e.Attributes.URI != nil && len(*e.Attributes.URI) > URILimit || e.Attributes.Body != nil && len(*e.Attributes.Body) > BodyLimit {
			t.Fatal("limit exceeded")
		}
	})
}

func TestRedactEvidence(t *testing.T) {
	t.Run("cowrie credentials command and freeform", func(t *testing.T) {
		r := baseCowrie()
		r["username"] = "credential-user"
		r["input"] = "curl --password command-secret https://user:url-secret@example.invalid/?token=uri-secret"
		r["message"] = "message-secret"
		r["unknown"] = map[string]any{"token": "unknown-secret"}
		e := decode(t, "cowrie", r, contextFor("ssh"))
		absent(t, e, "cowrie-secret", "credential-user", "command-secret", "url-secret", "uri-secret", "message-secret", "unknown-secret")
		if e.Attributes.Password == nil || *e.Attributes.Password != "[REDACTED]" {
			t.Fatal("credential marker missing")
		}
		r["input"] = "echo harmless"
		e = decode(t, "cowrie", r, contextFor("ssh"))
		if e.Attributes.Command == nil || *e.Attributes.Command != "echo harmless" {
			t.Fatal("safe command evidence lost")
		}
	})
	t.Run("query headers and nested json", func(t *testing.T) {
		r := baseWeb()
		r["uri"] = "/search?%74oken=query-secret&password=pass-secret&api_key=key-secret&q=visible&tag=one&tag=two"
		r["headers"] = []domain.Header{{Name: "Authorization", Value: "Bearer auth-secret"}, {Name: "cOoKiE", Value: "session=cookie-secret"}, {Name: "X-Api-Key", Value: "header-secret"}, {Name: "Content-Type", Value: "application/json"}, {Name: "X-Forwarded-For", Value: "203.0.113.99"}}
		r["body"] = `{"password":"json-secret","nested":[{"access_token":"nested-secret","action":"scan"}],"safe":"visible"}`
		e := decode(t, "web", r, contextFor("http"))
		absent(t, e, "query-secret", "pass-secret", "key-secret", "auth-secret", "cookie-secret", "header-secret", "json-secret", "nested-secret")
		if e.SourceIP != "198.51.100.20" || e.Attributes.URI == nil || !strings.Contains(*e.Attributes.URI, "q=visible") || !strings.Contains(*e.Attributes.URI, "tag=one&tag=two") || e.Attributes.Body == nil || !strings.Contains(*e.Attributes.Body, "scan") {
			t.Fatal("safe structured evidence lost")
		}
	})
	cases := []struct{ name, contentType, body, uri, secret string }{
		{"form", "application/x-www-form-urlencoded", "user=joe&password=form-secret&action=scan", "/", "form-secret"},
		{"malformed json", "application/json", `{"password":"malformed-secret"`, "/", "malformed-secret"},
		{"unsupported multipart", "multipart/form-data; boundary=x", "multipart-secret", "/", "multipart-secret"},
		{"encoded body", "text/plain", "password%3Dencoded-secret", "/", "encoded-secret"},
		{"plaintext credentials", "text/plain", "password=text-secret action=scan", "/", "text-secret"},
		{"invalid query escape", "text/plain", "ok", "/?token=escape-secret%ZZ", "escape-secret"},
		{"double encoded query", "text/plain", "ok", "/?%2574oken=double-secret", "double-secret"},
		{"absolute URI userinfo", "text/plain", "ok", "http://user:userinfo-secret@example.invalid/a?q=ok", "userinfo-secret"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := baseWeb()
			r["headers"] = []domain.Header{{Name: "content-type", Value: tc.contentType}}
			r["body"] = tc.body
			r["uri"] = tc.uri
			e := decode(t, "web", r, contextFor("http"))
			absent(t, e, tc.secret)
			if !slices.Contains(e.QualityFlags, "body_redacted") && !slices.Contains(e.QualityFlags, "uri_redacted") {
				t.Fatal("redaction not visible in quality")
			}
		})
	}
	t.Run("truncated and duplicate structured secrets fail closed", func(t *testing.T) {
		for _, body := range []string{`{"password":"truncated-secret`, `{"safe":"one","safe":"duplicate-secret"}`} {
			r := baseWeb()
			r["body"] = body
			r["headers"] = []domain.Header{{Name: "content-type", Value: "application/json"}}
			r["truncation"] = map[string]any{"body": domain.Truncation{Limit: BodyLimit, Observed: BodyLimit + 1, Retained: BodyLimit, Truncated: true}}
			e := decode(t, "web", r, contextFor("http"))
			absent(t, e, "truncated-secret", "duplicate-secret")
			flagged(t, e, "body_truncated")
			flagged(t, e, "body_redacted")
		}
	})
	t.Run("attacker context fields nested in body remain only evidence", func(t *testing.T) {
		r := baseWeb()
		r["headers"] = []domain.Header{{Name: "content-type", Value: "application/json"}}
		r["body"] = `{"is_test":true,"source_ip":"203.0.113.99","destination_ip":"203.0.113.66"}`
		e := decode(t, "web", r, contextFor("http"))
		if e.IsTest || e.SourceIP != "198.51.100.20" || e.DestinationIP != "192.0.2.10" {
			t.Fatal("body changed trusted event identity")
		}
	})
}

func TestRedactEvidenceAmbiguity(t *testing.T) {
	t.Run("credential CLI options", func(t *testing.T) {
		for _, command := range []string{"curl -u alice:cli-value", "mysql -p cli-value", "sshpass -p cli-value", "curl --user alice:cli-value"} {
			r := baseCowrie()
			r["input"] = command
			e := decode(t, "cowrie", r, contextFor("ssh"))
			absent(t, e, "cli-value")
			flagged(t, e, "command_redacted")
		}
	})
	t.Run("text credential aliases", func(t *testing.T) {
		for _, body := range []string{"pwd=alias-value", "auth=alias-value", "session_id=alias-value", "username=alias-value"} {
			r := baseWeb()
			r["body"] = body
			e := decode(t, "web", r, contextFor("http"))
			absent(t, e, "alias-value")
			flagged(t, e, "body_redacted")
		}
	})
	t.Run("ambiguous engine keys", func(t *testing.T) {
		raw := encoded(t, baseWeb())
		raw = append(raw[:len(raw)-1], []byte(`,"PEER_IP":"203.0.113.66"}`)...)
		if _, err := DecodeWeb(raw, contextFor("http")); err == nil {
			t.Fatal("accepted case-colliding envelope keys")
		}
	})
	t.Run("flagged structured truncation", func(t *testing.T) {
		r := baseWeb()
		r["headers"] = []domain.Header{{Name: "content-type", Value: "application/json"}}
		r["body"] = `{"safe":"ambiguous-value"}`
		r["quality_flags"] = []string{"body_truncated"}
		e := decode(t, "web", r, contextFor("http"))
		absent(t, e, "ambiguous-value")
		flagged(t, e, "body_redaction_limited")
	})
	t.Run("encoded and ambiguous content type", func(t *testing.T) {
		for _, headers := range [][]domain.Header{{{Name: "content-type", Value: "text/plain"}, {Name: "content-encoding", Value: "gzip"}}, {{Name: "content-type", Value: "text/plain"}, {Name: "Content-Type", Value: "application/json"}}} {
			r := baseWeb()
			r["headers"] = headers
			r["body"] = "encoded-value"
			e := decode(t, "web", r, contextFor("http"))
			absent(t, e, "encoded-value")
			flagged(t, e, "body_redaction_limited")
		}
	})
	t.Run("exact raw hash includes provided whitespace", func(t *testing.T) {
		raw := append(encoded(t, baseCowrie()), '\n')
		e, err := DecodeCowrie(raw, contextFor("ssh"))
		if err != nil {
			t.Fatal(err)
		}
		if e.RawHash != digest(raw) || e.RawHash == digest(bytes.TrimSpace(raw)) {
			t.Fatal("raw hash changed framing")
		}
	})
}

func TestDecodeEngineEvidenceDeterministic(t *testing.T) {
	r := baseWeb()
	r["body"] = nil
	r["headers"] = nil
	r["uri"] = nil
	r["method"] = nil
	r["truncation"] = map[string]any{"body": domain.Truncation{Limit: BodyLimit, Observed: 2, Retained: 1, Truncated: true}, "uri": domain.Truncation{Limit: URILimit, Observed: 2, Retained: 1, Truncated: true}, "headers": domain.Truncation{Limit: HeaderLimit, Observed: 2, Retained: 1, Truncated: true}, "record": domain.Truncation{Limit: RecordLimit, Observed: 2, Retained: 1, Truncated: true}}
	first := encoded(t, decode(t, "web", r, contextFor("http")))
	for i := 0; i < 100; i++ {
		if !bytes.Equal(first, encoded(t, decode(t, "web", r, contextFor("http")))) {
			t.Fatal("identical pure decoding produced different canonical output")
		}
	}
}

func TestRedactEvidenceOutputBounds(t *testing.T) {
	t.Run("expanded redacted headers stay bounded", func(t *testing.T) {
		r := baseWeb()
		headers := make([]domain.Header, 1000)
		for i := range headers {
			headers[i] = domain.Header{Name: "x-token", Value: ""}
		}
		r["headers"] = headers
		e := decode(t, "web", r, contextFor("http"))
		size := 0
		for _, h := range *e.Attributes.Headers {
			size += len(h.Name) + len(h.Value) + 4
		}
		if size > HeaderLimit {
			t.Fatalf("redacted output headers exceed limit: %d", size)
		}
	})
	t.Run("unsupported textual encoding", func(t *testing.T) {
		for _, headers := range [][]domain.Header{{{Name: "content-type", Value: "text/plain; charset=iso-8859-1"}}, {{Name: "content-type", Value: "text/plain"}, {Name: "content-transfer-encoding", Value: "base64"}}} {
			r := baseWeb()
			r["headers"] = headers
			r["body"] = "opaque-value"
			e := decode(t, "web", r, contextFor("http"))
			absent(t, e, "opaque-value")
			flagged(t, e, "body_redaction_limited")
		}
	})
	t.Run("text labeled structured credentials", func(t *testing.T) {
		for _, body := range []string{`{"pwd":"unseen-value"}`, `<pwd>unseen-value</pwd>`, `pwd = unseen-value`} {
			r := baseWeb()
			r["body"] = body
			e := decode(t, "web", r, contextFor("http"))
			absent(t, e, "unseen-value")
			flagged(t, e, "body_redaction_limited")
		}
	})
}

func TestRedactEvidenceAttachedCredentialOptions(t *testing.T) {
	const marker = "reviewvalue397"
	for _, command := range []string{
		"mysql -p" + marker,
		"curl -ualice:" + marker + " https://example.invalid/",
		"mysql\t-p" + marker,
		"curl\t-ualice:" + marker + " https://example.invalid/",
		"mysql -p\t" + marker,
		"curl -u\talice:" + marker + " https://example.invalid/",
		"mysql\n-p" + marker,
		"mysql -p'" + marker + "'",
	} {
		t.Run(command, func(t *testing.T) {
			r := baseCowrie()
			r["input"] = command
			e := decode(t, "cowrie", r, contextFor("ssh"))
			absent(t, e, marker)
			flagged(t, e, "command_redacted")
		})
	}
	for _, command := range []string{"echo harmless", "ls -la /tmp", "wget https://example.invalid/", "echo non-option-pvalue"} {
		t.Run("preserve "+command, func(t *testing.T) {
			r := baseCowrie()
			r["input"] = command
			e := decode(t, "cowrie", r, contextFor("ssh"))
			if e.Attributes.Command == nil || *e.Attributes.Command != command {
				t.Fatal("ordinary command evidence lost")
			}
		})
	}
}

func TestRedactEvidenceQuotedCredentialOptions(t *testing.T) {
	const marker = "reviewvalue397"
	for _, command := range []string{
		`mysql "-p` + marker + `"`,
		`curl '-ualice:` + marker + `' https://example.invalid/`,
		`mysql -'p'` + marker,
		`mysql -\p` + marker,
	} {
		t.Run(command, func(t *testing.T) {
			r := baseCowrie()
			r["input"] = command
			e := decode(t, "cowrie", r, contextFor("ssh"))
			absent(t, e, marker)
			flagged(t, e, "command_redacted")
			flagged(t, e, "command_redaction_limited")
		})
	}
	// Quotes and escapes require shell interpretation even without known secrets;
	// this bounded adapter records the limitation instead of interpreting them.
	for _, command := range []string{`echo 'hello'`, `echo "hello"`, `echo hello\ world`} {
		t.Run("ambiguous "+command, func(t *testing.T) {
			r := baseCowrie()
			r["input"] = command
			e := decode(t, "cowrie", r, contextFor("ssh"))
			if e.Attributes.Command == nil || *e.Attributes.Command != "[REDACTED]" {
				t.Fatal("ambiguous command tokenization was treated as complete")
			}
			flagged(t, e, "command_redaction_limited")
		})
	}
}
