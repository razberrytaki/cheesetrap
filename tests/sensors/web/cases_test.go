package web

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

type Repeat struct {
	ASCII       string `json:"ascii"`
	Bytes       int    `json:"bytes"`
	RepeatBytes int    `json:"repeat_bytes"`
}
type Input struct {
	Method       string                     `json:"method"`
	Target       string                     `json:"target"`
	TargetPrefix string                     `json:"target_prefix"`
	TargetRepeat Repeat                     `json:"target_repeat"`
	Headers      map[string]json.RawMessage `json:"headers"`
	Body         string                     `json:"body_utf8"`
	BodyRepeat   Repeat                     `json:"body_repeat"`
	Raw          string                     `json:"raw_utf8"`
	Disconnect   bool                       `json:"disconnect"`
}
type Case struct {
	ID       string `json:"case_id"`
	Protocol string `json:"protocol"`
	Input    Input  `json:"input"`
}

func Hash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func LoadCases(path string) ([]Case, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return nil, e
	}
	var doc struct {
		Cases []Case `json:"cases"`
	}
	if e = json.Unmarshal(b, &doc); e != nil {
		return nil, e
	}
	var out []Case
	for _, c := range doc.Cases {
		if c.Protocol == "http" || c.Protocol == "https" {
			out = append(out, c)
		}
	}
	return out, nil
}
func repeated(r Repeat) (string, error) {
	n := r.Bytes
	if r.RepeatBytes != 0 {
		n = r.RepeatBytes
	}
	if n < 0 || n > 1<<20 || len(r.ASCII) > 1 {
		return "", fmt.Errorf("invalid bounded repeat")
	}
	return strings.Repeat(r.ASCII, n), nil
}
func (c Case) Bytes(host string) ([]byte, error) {
	if strings.ContainsAny(host, "\r\n") {
		return nil, fmt.Errorf("invalid Host")
	}
	if c.Input.Raw != "" {
		return []byte(c.Input.Raw), nil
	}
	target := c.Input.Target
	if c.Input.TargetRepeat.Bytes > 0 {
		s, e := repeated(c.Input.TargetRepeat)
		if e != nil {
			return nil, e
		}
		target = c.Input.TargetPrefix + s
	}
	body := c.Input.Body
	if c.Input.BodyRepeat.Bytes > 0 {
		s, e := repeated(c.Input.BodyRepeat)
		if e != nil {
			return nil, e
		}
		body = s
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n", c.Input.Method, target, host)
	names := make([]string, 0, len(c.Input.Headers))
	for k := range c.Input.Headers {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		var v string
		if e := json.Unmarshal(c.Input.Headers[k], &v); e != nil {
			var r Repeat
			if e = json.Unmarshal(c.Input.Headers[k], &r); e != nil {
				return nil, e
			}
			v, e = repeated(r)
			if e != nil {
				return nil, e
			}
		}
		fmt.Fprintf(&b, "%s: %s\r\n", k, v)
	}
	if body != "" || c.Input.Method == "POST" {
		fmt.Fprintf(&b, "Content-Length: %d\r\n", len(body))
	}
	b.WriteString("\r\n")
	b.WriteString(body)
	return []byte(b.String()), nil
}
