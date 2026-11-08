package reporting

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"sort"
	"time"

	"cheesetrap/internal/detection"
	"cheesetrap/internal/domain"
	"cheesetrap/internal/enrichment"
	"cheesetrap/internal/store/db"

	"github.com/jackc/pgx/v5"
)

func prepareRevision(ctx context.Context, q *db.Queries, r *domain.ReportRevision, selection *string) error {
	now, err := q.ReportRevisionClock(ctx)
	if err != nil {
		return revisionError(ctx)
	}
	reasons := map[string]bool{}
	r.AutoApprovalAllowed = false
	err = r.Snapshot.EachRule(func(rule domain.ReportRule) error {
		if !rule.EvidenceEligible {
			reasons["evidence_ineligible"] = true
		}
		var explanation detection.Explanation
		if json.Unmarshal(rule.Explanation, &explanation) != nil {
			return ErrRevisionFailed
		}
		for _, reason := range explanation.HoldReasons {
			reasons[reason] = true
		}
		return nil
	})
	if err != nil {
		return ErrRevisionFailed
	}
	err = r.Snapshot.EachEvidence(func(e domain.ReportEvidence) error {
		for _, flag := range e.QualityFlags {
			switch flag {
			case "credentials_redacted", "headers_redacted", "body_redacted", "uri_redacted", "command_redacted":
			default:
				reasons[flag] = true
			}
		}
		if len(e.CollectionGap) > 0 {
			reasons["collection_gap"] = true
		}
		if e.IsTest {
			reasons["test_evidence"] = true
		}
		if e.ObservedAt.IsZero() {
			reasons["observed_at_missing"] = true
		}
		if _, ok := enrichment.PublicAddress(e.DestinationIP); !ok || e.DestinationPort < 1 || e.DestinationPort > 65535 {
			reasons["destination_not_public"] = true
		}
		return nil
	})
	if err != nil {
		return ErrRevisionFailed
	}
	if r.Snapshot.ObservedEnd.IsZero() {
		reasons["observed_at_missing"] = true
	} else if now.Time.Sub(r.Snapshot.ObservedEnd) > 72*time.Hour {
		reasons["stale_evidence"] = true
	}
	r.ReplyTo = ""
	setting, err := q.GetSetting(ctx, "reporting_reply_to")
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return revisionError(ctx)
	}
	if err == nil {
		var value struct {
			Address string `json:"address"`
		}
		if json.Unmarshal(setting.Value, &value) == nil {
			r.ReplyTo, _ = enrichment.Mailbox(value.Address)
		}
	}
	if r.ReplyTo == "" {
		reasons["reply_to_missing"] = true
	}
	var registry enrichment.Result
	if json.Unmarshal(r.Snapshot.Registry, &registry) != nil {
		return ErrRevisionFailed
	}
	candidates := verifiedContacts(registry, r.Snapshot.SourceIP)
	fresh := registry.LookupSucceeded && !registry.QueriedAt.IsZero() && !registry.QueriedAt.After(now.Time) && registry.ExpiresAt.After(now.Time)
	if selection != nil {
		address, ok := enrichment.Mailbox(*selection)
		if !ok || !fresh || !candidates[address] {
			return ErrRevisionInput
		}
		r.Recipient = address
	}
	if r.Recipient == "" && len(candidates) == 1 && fresh && registry.HeldReason == "" {
		for address := range candidates {
			r.Recipient = address
		}
	}
	if r.Recipient != "" && !candidates[r.Recipient] {
		return ErrRevisionInput
	}
	if !registry.LookupSucceeded {
		reason := registry.HeldReason
		if reason == "" {
			reason = "contact_lookup_failed"
		}
		reasons[reason] = true
	}
	if registry.Address != r.Snapshot.SourceIP {
		reasons["contact_address_mismatch"] = true
	}
	if registry.LookupSucceeded && !fresh {
		reasons["contact_expired"] = true
	}
	if len(candidates) == 0 {
		reasons["contact_missing"] = true
	}
	if r.Recipient == "" && len(candidates) > 1 {
		reasons["contact_ambiguous"] = true
	}
	if registry.HeldReason != "" && registry.HeldReason != "contact_ambiguous" {
		reasons[registry.HeldReason] = true
	}
	r.HoldReasons = []string{}
	for reason := range reasons {
		r.HoldReasons = append(r.HoldReasons, reason)
	}
	sort.Strings(r.HoldReasons)
	r.State = "needs_review"
	if len(r.HoldReasons) > 0 {
		r.State = "held"
		r.AutoApprovalAllowed = false
	}
	return nil
}
func verifiedContacts(r enrichment.Result, source string) map[string]bool {
	return contactsWithSource(r, source)
}

func contactsWithSource(r enrichment.Result, source string) map[string]bool {
	result := map[string]bool{}
	ip, err := netip.ParseAddr(source)
	if err != nil || r.Address != source || !r.LookupSucceeded {
		return result
	}
	for _, c := range r.Candidates {
		address, ok := enrichment.Mailbox(c.Email)
		if !ok || c.Role != "abuse" || len(c.Sources) == 0 {
			continue
		}
		valid := false
		for _, s := range c.Sources {
			start, e1 := netip.ParseAddr(s.NetworkStart)
			end, e2 := netip.ParseAddr(s.NetworkEnd)
			if e1 == nil && e2 == nil && s.Role == "abuse" && (s.Method == "rdap" || s.Method == "whois") && s.SourceURL != "" && start.Is4() == ip.Is4() && end.Is4() == ip.Is4() && start.Compare(ip) <= 0 && end.Compare(ip) >= 0 {
				valid = true
			}
		}
		if valid {
			result[address] = true
		}
	}
	return result
}
