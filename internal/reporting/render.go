package reporting

import (
	"bytes"
	_ "embed"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"text/template"
	"unicode"
	"unicode/utf8"

	"cheesetrap/internal/domain"
	"cheesetrap/internal/enrichment"
)

//go:embed templates/abuse.txt
var abuseTemplate string
var abuse = template.Must(template.New("abuse").Parse(abuseTemplate))

// Plaintext keeps hostile evidence on its own line and exposes control bytes.
func plain(s string) string {
	var b strings.Builder
	for _, r := range strings.ToValidUTF8(s, "�") {
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf) {
			fmt.Fprintf(&b, "\\u%04x", r)
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}
func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	s = s[:n]
	for !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}
func endpoint(e domain.ReportEvidence) string {
	if _, ok := enrichment.PublicAddress(e.DestinationIP); !ok || e.DestinationPort < 1 || e.DestinationPort > 65535 {
		return "unavailable"
	}
	return net.JoinHostPort(e.DestinationIP, strconv.Itoa(e.DestinationPort))
}

// Translate metadata only. Commands and request paths remain evidence text;
// unknown event types must not be presented as confirmed authentication failures.
func eventDescription(e domain.ReportEvidence) string {
	if e.Service == "ssh" {
		switch e.EventType {
		case "cowrie.login.failed":
			return "SSH authentication failed"
		case "cowrie.login.success":
			return "SSH authentication accepted"
		case "cowrie.command.input":
			return "SSH command submitted"
		case "cowrie.session.connect":
			return "SSH connection opened"
		case "cowrie.session.closed":
			return "SSH connection closed"
		}
		return "SSH event"
	}
	if (e.Service == "http" || e.Service == "https") && e.EventType == "web.request" {
		return "HTTP request"
	}
	return "Network event"
}

// Render is deterministic and uses only immutable revision contents. Revision
// UUID/version/time are metadata outside the signed content, not body text.
func Render(r domain.ReportRevision) (string, string, error) {
	for _, m := range []string{r.Recipient, r.ReplyTo} {
		if m != "" {
			if _, ok := enrichment.Mailbox(m); !ok {
				return "", "", ErrRevisionInput
			}
		}
	}
	subject := "Abuse report: " + r.Snapshot.SourceIP + " [" + r.ReportID + "]"
	if !ValidHeader(subject) {
		return "", "", ErrRevisionInput
	}
	endpoints := []string{}
	seen := map[string]bool{}
	var excerpts strings.Builder
	retained := 0
	truncated := false
	summaryTruncated := false
	endpointBytes := 0
	err := r.Snapshot.EachEvidence(func(e domain.ReportEvidence) error {
		ep := plain(e.Service) + " " + endpoint(e)
		if !seen[ep] {
			if endpointBytes+len(ep)+1 <= 256*1024 {
				endpoints = append(endpoints, ep)
				seen[ep] = true
				endpointBytes += len(ep) + 1
			} else {
				summaryTruncated = true
			}
		}
		// UTF-8 clipping can leave spare bytes without a terminating newline.
		// Keep collecting endpoints, but never append another record's prefix.
		if truncated {
			return nil
		}
		line := e.ObservedAt.UTC().Format("2006-01-02T15:04:05Z07:00") + " " + plain(e.SourceIP) + " event_id=" + plain(e.EventID) + " -> " + ep + " " + eventDescription(e)
		if e.Method != "" {
			line += " method=" + plain(e.Method)
		}
		if e.URI != "" {
			line += " uri=" + plain(e.URI)
		}
		if e.Command != "" {
			line += " command=" + plain(e.Command)
		}
		line += "\n"
		if retained >= 50 || excerpts.Len() >= 32*1024 {
			truncated = true
			return nil
		}
		room := 32*1024 - excerpts.Len()
		if len(line) > room {
			line = clip(line, room)
			truncated = true
		}
		excerpts.WriteString(line)
		retained++
		return nil
	})
	if err != nil {
		return "", "", err
	}
	total, _ := r.Snapshot.Counts()
	if retained < total {
		truncated = true
	}

	// Rule windows can overlap; their match/context counts are not event totals.
	// A fixed vocabulary keeps the recipient summary bounded and engine-neutral.
	activities := map[string]bool{}
	err = r.Snapshot.EachRule(func(rule domain.ReportRule) error {
		description := "Network activity requiring review"
		switch rule.RuleID {
		case "SSH-REPEAT":
			description = "repeated failed SSH authentication attempts"
		case "WEB-REPEAT":
			description = "repeated HTTP requests for suspicious paths"
		case "WEB-EXPLOIT":
			description = "HTTP requests matching a path traversal pattern"
		}
		activities[description] = true
		return nil
	})
	if err != nil {
		return "", "", err
	}
	activityLines := []string{}
	for description := range activities {
		activityLines = append(activityLines, description)
	}
	sort.Strings(activityLines)
	if len(activityLines) == 0 {
		activityLines = append(activityLines, "Network activity requiring review")
	}
	data := struct {
		ReportID, SourceIP, Start, End, Endpoints, Activities, ReplyTo, Excerpts string
		Delayed, Truncated, SummaryTruncated                                     bool
		Total, Retained                                                          int
	}{
		ReportID: plain(r.ReportID), SourceIP: plain(r.Snapshot.SourceIP),
		Start:     r.Snapshot.ObservedStart.UTC().Format("2006-01-02T15:04:05Z07:00"),
		End:       r.Snapshot.ObservedEnd.UTC().Format("2006-01-02T15:04:05Z07:00"),
		Endpoints: strings.Join(endpoints, "\n"), Activities: strings.Join(activityLines, "\n"),
		ReplyTo: r.ReplyTo, Excerpts: strings.TrimSuffix(excerpts.String(), "\n"),
		Delayed: r.Snapshot.DelayedCollection, Truncated: truncated, SummaryTruncated: summaryTruncated,
		Total: total, Retained: retained,
	}
	var out bytes.Buffer
	if err := abuse.Execute(&out, data); err != nil {
		return "", "", ErrRevisionInput
	}
	return subject, out.String(), nil
}

// ValidHeader validates the immutable draft subject.
func ValidHeader(s string) bool {
	if s == "" || len(s) > 998 || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf) {
			return false
		}
	}
	return true
}
