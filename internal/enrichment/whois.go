package enrichment

import (
	"context"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

// Only RIPE has an explicitly supported fallback query. Its documented -b
// output associates abuse-mailbox with the resource's inetnum/inet6num key.
// https://docs.db.ripe.net/Types-of-Queries/Abuse-Contacts/
func (r *resolver) lookupWHOIS(ctx context.Context, ip netip.Addr) (Result, error) {
	host := "whois.ripe.net"
	seen := map[string]bool{}
	for hop := 0; hop <= maxReferrals; hop++ {
		if seen[host] {
			return Result{}, errUnsafe
		}
		seen[host] = true
		requestCtx, cancel := context.WithTimeout(ctx, requestTimeout)
		release, err := r.gate.acquire(requestCtx, host)
		if err != nil {
			cancel()
			return Result{}, err
		}
		body, err := r.whoisQuery(requestCtx, host, "-b "+ip.String()+"\r\n")
		release(time.Time{})
		cancel()
		if err != nil {
			return Result{}, err
		}
		if len(body) > maxResponse {
			return Result{}, errLarge
		}
		referral, err := whoisReferral(body)
		if err != nil {
			return Result{}, err
		}
		if referral != "" {
			host = referral
			continue
		}
		return parseWHOIS(body, ip, host)
	}
	return Result{}, errUnsafe
}
func whoisReferral(body string) (string, error) {
	target := ""
	for _, line := range strings.Split(body, "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		if key != "refer" && key != "referralserver" && key != "whois" {
			continue
		}
		raw := strings.TrimSpace(value)
		if !strings.Contains(raw, "://") {
			raw = "whois://" + raw
		}
		u, err := url.Parse(raw)
		if err != nil || u.Scheme != "whois" || u.Hostname() != "whois.ripe.net" || (u.Port() != "" && u.Port() != "43") || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" {
			return "", errUnsafe
		}
		if target != "" && target != u.Hostname() {
			return "", errUnsafe
		}
		target = u.Hostname()
	}
	return target, nil
}

type whoisObject struct {
	start, end netip.Addr
	emails     []string
	valid      bool
}

func parseWHOIS(body string, ip netip.Addr, host string) (Result, error) {
	objects := []whoisObject{}
	current := whoisObject{}
	keys := 0
	hasRoute := false
	bad := false
	flush := func() {
		if current.valid {
			objects = append(objects, current)
		}
		current = whoisObject{}
		keys = 0
		hasRoute = false
	}
	for _, line := range strings.Split(strings.ReplaceAll(body, "\r\n", "\n"), "\n") {
		if strings.TrimSpace(line) == "" {
			flush()
			continue
		}
		if strings.HasPrefix(line, "%") || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		switch key {
		case "inetnum", "inet6num":
			keys++
			if keys > 1 || hasRoute {
				bad = true
				continue
			}
			if key == "inetnum" {
				parts := strings.Split(value, "-")
				if len(parts) != 2 {
					bad = true
					continue
				}
				a, startErr := netip.ParseAddr(strings.TrimSpace(parts[0]))
				b, endErr := netip.ParseAddr(strings.TrimSpace(parts[1]))
				// Validate the resource itself before testing containment. A broken
				// child must not disappear and expose a broader parent's contact.
				if startErr != nil || endErr != nil || !a.Is4() || !b.Is4() || a.Zone() != "" || b.Zone() != "" || a.Compare(b) > 0 {
					bad = true
					continue
				}
				current.start = a
				current.end = b
				current.valid = ip.Is4() && a.Compare(ip) <= 0 && b.Compare(ip) >= 0
			} else {
				p, err := netip.ParsePrefix(value)
				if err != nil || p.Addr().Is4() || p.Addr().Is4In6() || p != p.Masked() {
					bad = true
					continue
				}
				bytes := p.Addr().As16()
				for bit := p.Bits(); bit < 128; bit++ {
					bytes[bit/8] |= 1 << uint(7-bit%8)
				}
				current.start = p.Addr()
				current.end = netip.AddrFrom16(bytes)
				current.valid = p.Contains(ip)
			}
		case "abuse-mailbox":
			current.emails = append(current.emails, value)
		case "route", "route6":
			hasRoute = true
			bad = bad || keys > 0
			current.valid = false
		}
	}
	flush()
	if bad || len(objects) == 0 {
		return Result{}, errInvalid
	}
	best := objects[0]
	// Ranges containing the same address must nest; crossing ranges are
	// contradictory and cannot establish a unique most-specific resource.
	for _, obj := range objects[1:] {
		if obj.start.Compare(best.start) >= 0 && obj.end.Compare(best.end) <= 0 {
			if obj.start == best.start && obj.end == best.end {
				best.emails = append(best.emails, obj.emails...)
			} else {
				best = obj
			}
		} else if !(best.start.Compare(obj.start) >= 0 && best.end.Compare(obj.end) <= 0) {
			return Result{}, errInvalid
		}
	}
	result := held(ip.String(), "")
	result.Method = "whois"
	result.SourceURL = "whois://" + host + ":43"
	result.NetworkStart = best.start.String()
	result.NetworkEnd = best.end.String()
	contacts := []Contact{}
	invalid := false
	for _, raw := range best.emails {
		email, ok := mailbox(raw)
		if !ok {
			invalid = true
			continue
		}
		contacts = append(contacts, Contact{Email: email, Role: "abuse", Method: result.Method, SourceURL: result.SourceURL, NetworkStart: result.NetworkStart, NetworkEnd: result.NetworkEnd})
	}
	finalizeContacts(&result, contacts, invalid)
	return result, nil
}
