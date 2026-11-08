package enrichment

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/mail"
	"sort"
	"strings"
	"time"
)

// Source records the registry object that explicitly assigned the abuse role.
// WHOIS is unauthenticated plain TCP; its method/source stay visible to callers.
type Source struct {
	Role         string `json:"role"`
	Method       string `json:"method"`
	SourceURL    string `json:"source_url"`
	NetworkStart string `json:"network_start"`
	NetworkEnd   string `json:"network_end"`
	Handle       string `json:"handle,omitempty"`
}
type Contact struct {
	Email        string   `json:"email"`
	Role         string   `json:"role"`
	Method       string   `json:"method"`
	SourceURL    string   `json:"source_url"`
	NetworkStart string   `json:"network_start"`
	NetworkEnd   string   `json:"network_end"`
	Handle       string   `json:"handle,omitempty"`
	Sources      []Source `json:"sources"`
}
type Result struct {
	SchemaVersion   int       `json:"schema_version"`
	Address         string    `json:"address"`
	Method          string    `json:"method,omitempty"`
	SourceURL       string    `json:"source_url,omitempty"`
	NetworkStart    string    `json:"network_start,omitempty"`
	NetworkEnd      string    `json:"network_end,omitempty"`
	Handle          string    `json:"handle,omitempty"`
	HeldReason      string    `json:"held_reason,omitempty"`
	Candidates      []Contact `json:"candidates"`
	LookupSucceeded bool      `json:"lookup_succeeded"`
	QueriedAt       time.Time `json:"queried_at"`
	ExpiresAt       time.Time `json:"expires_at"`
	RetryAfter      time.Time `json:"retry_after,omitempty"`
}

func held(raw, reason string) Result {
	now := time.Now().UTC()
	return Result{SchemaVersion: 1, Address: raw, HeldReason: reason, Candidates: []Contact{}, QueriedAt: now, ExpiresAt: now.Add(time.Hour)}
}
func mailbox(raw string) (string, bool) {
	if len(raw) > 254 || strings.TrimSpace(raw) != raw || strings.ContainsAny(raw, "\r\n\t <>()[]:;,\\\"") {
		return "", false
	}
	for _, c := range raw {
		if c < 33 || c > 126 {
			return "", false
		}
	}
	at := strings.LastIndexByte(raw, '@')
	if at < 1 || at > 64 || strings.Count(raw, "@") != 1 {
		return "", false
	}
	domain := strings.ToLower(raw[at+1:])
	if !strings.Contains(domain, ".") || len(domain) > 253 {
		return "", false
	}
	for _, label := range strings.Split(domain, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", false
		}
		for _, c := range label {
			if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
				return "", false
			}
		}
	}
	parsed, err := mail.ParseAddress(raw)
	if err != nil || parsed.Address != raw || parsed.Name != "" {
		return "", false
	}
	return raw[:at+1] + domain, true
}
func finalizeContacts(result *Result, contacts []Contact, invalid bool) {
	byEmail := map[string][]Source{}
	for _, c := range contacts {
		byEmail[c.Email] = append(byEmail[c.Email], Source{c.Role, c.Method, c.SourceURL, c.NetworkStart, c.NetworkEnd, c.Handle})
	}
	result.Candidates = []Contact{}
	for email, sources := range byEmail {
		key := func(s Source) string { b, _ := json.Marshal(s); return string(b) }
		sort.Slice(sources, func(i, j int) bool { return key(sources[i]) < key(sources[j]) })
		unique := sources[:0]
		for _, s := range sources {
			if len(unique) == 0 || s != unique[len(unique)-1] {
				unique = append(unique, s)
			}
		}
		s := unique[0]
		result.Candidates = append(result.Candidates, Contact{email, s.Role, s.Method, s.SourceURL, s.NetworkStart, s.NetworkEnd, s.Handle, unique})
	}
	sort.Slice(result.Candidates, func(i, j int) bool { return result.Candidates[i].Email < result.Candidates[j].Email })
	result.LookupSucceeded = true
	result.ExpiresAt = result.QueriedAt.Add(24 * time.Hour)
	switch {
	case invalid:
		result.HeldReason = "contact_invalid"
	case len(result.Candidates) == 0:
		result.HeldReason = "contact_missing"
	case len(result.Candidates) > 1:
		result.HeldReason = "contact_ambiguous"
	default:
		result.HeldReason = ""
	}
}

// Registry protocol member names are ASCII. Reject non-ASCII names and
// case-insensitive duplicates (including escaped equivalents) before Go
// unmarshalling can fold Unicode names such as roles/roleſ into one field.
func decodeJSON(data []byte, target any) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 32 {
			return errors.New("invalid_response")
		}
		token, err := d.Token()
		if err != nil {
			return err
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			keys := map[string]bool{}
			for d.More() {
				token, err = d.Token()
				if err != nil {
					return err
				}
				key, ok := token.(string)
				for _, r := range key {
					if r > 127 {
						return errors.New("invalid_response")
					}
				}
				if !ok || keys[strings.ToLower(key)] {
					return errors.New("invalid_response")
				}
				keys[strings.ToLower(key)] = true
				if err = walk(depth + 1); err != nil {
					return err
				}
			}
		case '[':
			for d.More() {
				if err = walk(depth + 1); err != nil {
					return err
				}
			}
		default:
			return errors.New("invalid_response")
		}
		_, err = d.Token()
		return err
	}
	if err := walk(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("invalid_response")
	}
	return json.Unmarshal(data, target)
}

type entity struct {
	Roles    []string        `json:"roles"`
	Handle   string          `json:"handle"`
	VCard    json.RawMessage `json:"vcardArray"`
	Entities []entity        `json:"entities"`
}

func extractEntities(entities []entity, result Result) ([]Contact, bool, error) {
	contacts := []Contact{}
	invalid := false
	count := 0
	var walk func([]entity, int) error
	walk = func(list []entity, depth int) error {
		if depth > 8 {
			return errors.New("invalid_response")
		}
		for _, e := range list {
			count++
			if count > 1024 {
				return errors.New("invalid_response")
			}
			abuse := false
			for _, role := range e.Roles {
				if role == "abuse" {
					abuse = true
				}
			}
			if abuse && len(e.VCard) > 0 {
				var card []json.RawMessage
				if json.Unmarshal(e.VCard, &card) != nil || len(card) != 2 || string(card[0]) != `"vcard"` {
					invalid = true
				} else {
					var props [][]json.RawMessage
					if json.Unmarshal(card[1], &props) != nil || props == nil {
						invalid = true
					} else {
						for _, prop := range props {
							// Check the common property header before ignoring non-email
							// values. Multi-value non-email properties may have >4 items.
							var name, kind string
							var parameters map[string]json.RawMessage
							if len(prop) < 4 || json.Unmarshal(prop[0], &name) != nil || name == "" || json.Unmarshal(prop[1], &parameters) != nil || parameters == nil || json.Unmarshal(prop[2], &kind) != nil || kind == "" {
								invalid = true
								continue
							}
							if name != "email" {
								continue
							}
							var email string
							if len(prop) != 4 || kind != "text" || json.Unmarshal(prop[3], &email) != nil {
								invalid = true
								continue
							}
							normalized, ok := mailbox(email)
							if !ok {
								invalid = true
								continue
							}
							contacts = append(contacts, Contact{Email: normalized, Role: "abuse", Method: result.Method, SourceURL: result.SourceURL, NetworkStart: result.NetworkStart, NetworkEnd: result.NetworkEnd, Handle: e.Handle})
						}
					}
				}
			}
			if len(e.Entities) > 0 {
				if err := walk(e.Entities, depth+1); err != nil {
					return err
				}
			}
		}
		return nil
	}
	err := walk(entities, 0)
	return contacts, invalid, err
}

// Mailbox validates a bare ASCII mailbox for registry and report headers.
func Mailbox(raw string) (string, bool) { return mailbox(raw) }
