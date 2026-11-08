package enrichment

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"
)

const maxResponse = 1 << 20
const requestTimeout = 10 * time.Second
const lookupTimeout = 30 * time.Second
const maxReferrals = 3

var rirBases = map[string]string{"rdap.arin.net": "/registry/", "rdap.db.ripe.net": "/", "rdap.apnic.net": "/", "rdap.afrinic.net": "/rdap/", "rdap.lacnic.net": "/rdap/"}

type bootstrapEntry struct {
	prefix netip.Prefix
	base   string
}
type bootstrapCache struct {
	entries []bootstrapEntry
	expires time.Time
}
type resolver struct {
	client      *http.Client
	gate        *hostGate
	whoisQuery  func(context.Context, string, string) (string, error)
	bootstrapMu sync.Mutex
	bootstraps  map[bool]bootstrapCache
}

func newResolver() *resolver {
	r := &resolver{gate: productionGate, bootstraps: make(map[bool]bootstrapCache)}
	guard := newNetworkGuard()
	r.client = &http.Client{Transport: guard.transport(), CheckRedirect: r.checkRedirect}
	r.whoisQuery = guard.queryWHOIS
	return r
}
func validBase(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Opaque != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawPath != "" || u.Port() != "" {
		return false
	}
	path, ok := rirBases[u.Host]
	return ok && u.Path == path
}
func validLookupURL(u *url.URL, ip string) bool {
	if u == nil {
		return false
	}
	base, ok := rirBases[u.Host]
	return ok && u.Scheme == "https" && u.User == nil && u.Opaque == "" && u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" && u.RawPath == "" && u.Path == base+"ip/"+ip
}
func (r *resolver) checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) == 0 || len(via) > maxReferrals {
		return errUnsafe
	}
	first := via[0].URL
	_, ip, ok := strings.Cut(first.Path, "ip/")
	if !ok || !validLookupURL(first, ip) || !validLookupURL(req.URL, ip) {
		return errUnsafe
	}
	for _, previous := range via {
		if previous.URL.String() == req.URL.String() {
			return errUnsafe
		}
	}
	return nil
}
func (r *resolver) bootstrap(ctx context.Context, ip netip.Addr) (string, error) {
	// The mutex covers only local cache access; no network happens while locked.
	r.bootstrapMu.Lock()
	cached := r.bootstraps[ip.Is4()]
	r.bootstrapMu.Unlock()
	if time.Now().After(cached.expires) {
		family := "ipv6"
		if ip.Is4() {
			family = "ipv4"
		}
		data, _, err := r.fetch(ctx, "https://data.iana.org/rdap/"+family+".json")
		if err != nil {
			return "", err
		}
		var doc struct {
			Services [][][]string `json:"services"`
		}
		if decodeJSON(data, &doc) != nil || len(doc.Services) == 0 {
			return "", errInvalid
		}
		entries := []bootstrapEntry{}
		for _, service := range doc.Services {
			if len(service) != 2 || len(service[0]) == 0 || len(service[1]) == 0 {
				return "", errInvalid
			}
			for _, raw := range service[0] {
				prefix, err := netip.ParsePrefix(raw)
				if err != nil || prefix.Addr().Is4() != ip.Is4() || prefix.Addr().Is4In6() || prefix != prefix.Masked() {
					return "", errInvalid
				}
				for _, base := range service[1] {
					entries = append(entries, bootstrapEntry{prefix, base})
				}
			}
		}
		cached = bootstrapCache{entries, time.Now().Add(24 * time.Hour)}
		r.bootstrapMu.Lock()
		r.bootstraps[ip.Is4()] = cached
		r.bootstrapMu.Unlock()
	}
	best := -1
	for _, entry := range cached.entries {
		if entry.prefix.Contains(ip) && entry.prefix.Bits() > best {
			best = entry.prefix.Bits()
		}
	}
	if best < 0 {
		return "", errors.New("registry_missing")
	}
	// RFC 9224 service URLs are unordered. Choose HTTPS at the longest
	// matching prefix; never choose a broader resource to avoid an unsafe URL.
	selected := ""
	for _, entry := range cached.entries {
		if !entry.prefix.Contains(ip) || entry.prefix.Bits() != best || !validBase(entry.base) {
			continue
		}
		if selected != "" && selected != entry.base {
			return "", errInvalid
		}
		selected = entry.base
	}
	if selected == "" {
		return "", errUnsafe
	}
	return selected, nil
}
func (r *resolver) lookup(parent context.Context, raw string) (Result, error) {
	if err := parent.Err(); err != nil {
		return Result{}, err
	}
	ip, ok := publicAddress(raw)
	if !ok {
		return held(raw, "address_not_public"), nil
	}
	ctx, cancel := context.WithTimeout(parent, lookupTimeout)
	defer cancel()
	result := held(ip.String(), "lookup_failed")
	fail := func(err error) (Result, error) {
		if parent.Err() != nil {
			return Result{}, parent.Err()
		}
		result.HeldReason = reason(err)
		result.LookupSucceeded = false
		result.Candidates = []Contact{}
		result.ExpiresAt = result.QueriedAt.Add(time.Hour)
		var rate *rateError
		if errors.As(err, &rate) {
			result.RetryAfter = rate.until
			if rate.until.After(result.ExpiresAt) {
				result.ExpiresAt = rate.until
			}
		}
		return result, nil
	}
	base, err := r.bootstrap(ctx, ip)
	if err != nil {
		return fail(err)
	}
	endpoint := base + "ip/" + ip.String()
	data, source, err := r.fetch(ctx, endpoint)
	finalURL, _ := url.Parse(source)
	ripeFallback := validLookupURL(finalURL, ip.String()) && finalURL.Host == "rdap.db.ripe.net"
	result.Method = "rdap"
	if validLookupURL(finalURL, ip.String()) {
		result.SourceURL = source
	}
	if err != nil {
		if !fallbackEligible(err) {
			return fail(err)
		}
		if !ripeFallback {
			return fail(errors.New("fallback_unsupported"))
		}
		got, err := r.lookupWHOIS(ctx, ip)
		if err != nil {
			return fail(err)
		}
		if parent.Err() != nil {
			return Result{}, parent.Err()
		}
		return got, nil
	}
	var doc struct {
		ObjectClassName string   `json:"objectClassName"`
		Start           string   `json:"startAddress"`
		End             string   `json:"endAddress"`
		Version         string   `json:"ipVersion"`
		Handle          string   `json:"handle"`
		Entities        []entity `json:"entities"`
	}
	if decodeJSON(data, &doc) != nil || doc.ObjectClassName != "ip network" {
		return fail(errInvalid)
	}
	start, end, ok := networkRange(doc.Start, doc.End, doc.Version, ip)
	if !ok {
		return fail(errInvalid)
	}
	result.Method = "rdap"
	result.SourceURL = source
	result.NetworkStart = start.String()
	result.NetworkEnd = end.String()
	result.Handle = doc.Handle
	contacts, invalid, err := extractEntities(doc.Entities, result)
	if err != nil {
		return fail(err)
	}
	finalizeContacts(&result, contacts, invalid)
	if result.HeldReason == "contact_missing" && ripeFallback {
		supplement, err := r.lookupWHOIS(ctx, ip)
		if err != nil {
			return fail(err)
		}
		a, _ := netip.ParseAddr(supplement.NetworkStart)
		b, _ := netip.ParseAddr(supplement.NetworkEnd)
		if a.Compare(start) >= 0 && b.Compare(end) <= 0 && supplement.HeldReason != "contact_missing" {
			result = supplement
		}
	}
	if parent.Err() != nil {
		return Result{}, parent.Err()
	}
	return result, nil
}
