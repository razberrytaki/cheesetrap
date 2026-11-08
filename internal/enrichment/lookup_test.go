package enrichment

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

type registryCase struct {
	Name, IP, Start, End, Version, WantHeld string
	Emails, WantEmails                      []string
	Roles                                   []string
}
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func response(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
}
func document(c registryCase) string {
	entities := []any{}
	for _, email := range c.Emails {
		entities = append(entities, map[string]any{"roles": c.Roles, "handle": "ABUSE1", "vcardArray": []any{"vcard", []any{[]any{"email", map[string]any{}, "text", email}}}})
	}
	b, _ := json.Marshal(map[string]any{"objectClassName": "ip network", "startAddress": c.Start, "endAddress": c.End, "ipVersion": c.Version, "handle": "NET1", "entities": entities})
	return string(b)
}
func fixtureResolver(t *testing.T, handler func(*http.Request) (*http.Response, error)) *resolver {
	t.Helper()
	r := newResolver()
	r.client = &http.Client{Transport: roundTripFunc(handler), CheckRedirect: r.checkRedirect}
	r.gate = newHostGate(0)
	r.whoisQuery = func(context.Context, string, string) (string, error) { return "inetnum: 8.8.8.0 - 8.8.8.255\n", nil }
	return r
}
func bootstrapBody(ip string) string {
	if strings.Contains(ip, ":") {
		return `{"services":[[["2000::/3"],["https://rdap.arin.net/registry/"]],[["2a00::/12"],["https://rdap.db.ripe.net/"]]]}`
	}
	return `{"services":[[["0.0.0.0/0"],["https://rdap.arin.net/registry/"]],[["8.8.0.0/16"],["https://rdap.db.ripe.net/"]]]}`
}
func TestLookup(t *testing.T) {
	data, err := os.ReadFile("../../testdata/registry/cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []registryCase
	if err = json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			calls := 0
			r := fixtureResolver(t, func(req *http.Request) (*http.Response, error) {
				calls++
				if req.URL.Host == "data.iana.org" {
					return response(200, bootstrapBody(c.IP)), nil
				}
				if req.URL.Host != "rdap.db.ripe.net" {
					t.Errorf("longest-prefix bootstrap selected %s", req.URL.Host)
				}
				return response(200, document(c)), nil
			})
			got, err := r.lookup(context.Background(), c.IP)
			if err != nil {
				t.Fatal(err)
			}
			if got.HeldReason != c.WantHeld {
				t.Fatalf("held=%q want %q", got.HeldReason, c.WantHeld)
			}
			var emails []string
			for _, candidate := range got.Candidates {
				emails = append(emails, candidate.Email)
				if candidate.Role != "abuse" || candidate.Method != "rdap" || candidate.SourceURL == "" {
					t.Error("missing contact provenance")
				}
			}
			if strings.Join(emails, ",") != strings.Join(c.WantEmails, ",") {
				t.Fatalf("emails=%v want %v", emails, c.WantEmails)
			}
			if !got.LookupSucceeded || got.NetworkStart != c.Start || got.NetworkEnd != c.End || got.Method != "rdap" || got.QueriedAt.IsZero() || got.ExpiresAt.Sub(got.QueriedAt) != 24*time.Hour {
				t.Errorf("missing validated network or cache metadata: %+v", got)
			}
			if calls != 2 {
				t.Errorf("unexpected requests: %d", calls)
			}
		})
	}
	t.Run("special_and_malformed_addresses_never_request", func(t *testing.T) {
		r := fixtureResolver(t, func(*http.Request) (*http.Response, error) { t.Fatal("unsafe address made a request"); return nil, nil })
		for _, ip := range []string{"127.0.0.1", "::ffff:127.0.0.1", "192.0.2.1", "100.64.1.1", "192.31.196.1", "192.52.193.1", "192.175.48.1", "2001:db8::1", "2002::1", "2001:4860::1%eth0", "8.8.8.8/32", "8.8.8.8\r\n", "3fff::1"} {
			got, err := r.lookup(context.Background(), ip)
			if err != nil || got.HeldReason != "address_not_public" || got.LookupSucceeded {
				t.Errorf("%q accepted: %+v %v", ip, got, err)
			}
		}
	})
	t.Run("mapped_public_canonicalized", func(t *testing.T) {
		r := fixtureResolver(t, func(req *http.Request) (*http.Response, error) {
			if req.URL.Host == "data.iana.org" {
				return response(200, bootstrapBody("8.8.8.8")), nil
			}
			if req.URL.Path != "/ip/8.8.8.8" {
				t.Error("mapped IP not canonicalized")
			}
			return response(200, document(registryCase{Start: "8.8.8.0", End: "8.8.8.255", Version: "v4", Emails: []string{"abuse@example.net"}, Roles: []string{"abuse"}})), nil
		})
		got, err := r.lookup(context.Background(), "::ffff:8.8.8.8")
		if err != nil || got.Address != "8.8.8.8" || got.HeldReason != "" {
			t.Fatalf("canonicalization failed: %+v %v", got, err)
		}
	})
}

func TestLookupSafety(t *testing.T) {
	valid := document(registryCase{Start: "8.8.8.0", End: "8.8.8.255", Version: "v4", Emails: []string{"abuse@example.net"}, Roles: []string{"abuse"}})
	for _, tc := range []struct {
		name, body, held string
		status           int
	}{
		{"outside_network", strings.ReplaceAll(valid, "8.8.8.", "9.9.9."), "invalid_response", 200},
		{"wrong_family", strings.Replace(valid, `"v4"`, `"v6"`, 1), "invalid_response", 200},
		{"not_network", strings.Replace(valid, "ip network", "entity", 1), "invalid_response", 200},
		{"reversed_range", strings.ReplaceAll(valid, "8.8.8.0", "8.8.8.254"), "", 200},
		{"oversize", strings.Repeat("x", (1<<20)+1), "response_too_large", 200},
		{"rate_limit", "secret response", "rate_limited", 429},
		{"malformed", "invalid", "invalid_response", 200},
	} {
		if tc.name == "reversed_range" {
			tc.body = strings.Replace(tc.body, "8.8.8.255", "8.8.8.1", 1)
			tc.held = "invalid_response"
		}
		t.Run(tc.name, func(t *testing.T) {
			r := fixtureResolver(t, func(req *http.Request) (*http.Response, error) {
				if req.URL.Host == "data.iana.org" {
					return response(200, bootstrapBody("8.8.8.8")), nil
				}
				res := response(tc.status, tc.body)
				res.Header.Set("Retry-After", "120")
				return res, nil
			})
			got, err := r.lookup(context.Background(), "8.8.8.8")
			if err != nil || got.HeldReason != tc.held || got.LookupSucceeded || len(got.Candidates) != 0 {
				t.Fatalf("unsafe response accepted: %+v %v", got, err)
			}
			if tc.status == 429 && got.RetryAfter.Before(time.Now().Add(time.Minute)) {
				t.Error("Retry-After ignored")
			}
		})
	}
	t.Run("nested_entities_do_not_inherit_abuse", func(t *testing.T) {
		doc := `{"objectClassName":"ip network","startAddress":"8.8.8.0","endAddress":"8.8.8.255","ipVersion":"v4","entities":[{"roles":["abuse"],"entities":[{"roles":["technical"],"vcardArray":["vcard",[["email",{},"text","tech@example.net"]]]}]},{"roles":["administrative"],"entities":[{"roles":["abuse"],"vcardArray":["vcard",[["email",{},"text","abuse@example.net"]]]}]}]}`
		r := fixtureResolver(t, func(req *http.Request) (*http.Response, error) {
			if req.URL.Host == "data.iana.org" {
				return response(200, bootstrapBody("8.8.8.8")), nil
			}
			return response(200, doc), nil
		})
		got, err := r.lookup(context.Background(), "8.8.8.8")
		if err != nil || len(got.Candidates) != 1 || got.Candidates[0].Email != "abuse@example.net" {
			t.Fatalf("role inheritance wrong: %+v %v", got, err)
		}
	})
	t.Run("unsafe_bootstrap", func(t *testing.T) {
		for _, endpoint := range []string{"http://rdap.db.ripe.net/", "https://rdap.db.ripe.net.attacker.test/", "https://127.0.0.1/", "https://rdap.arin.net/other/", "https://rdap.db.ripe.net/?x=1"} {
			calls := 0
			r := fixtureResolver(t, func(*http.Request) (*http.Response, error) {
				calls++
				return response(200, `{"services":[[["8.8.8.0/24"],["`+endpoint+`"]]]}`), nil
			})
			got, err := r.lookup(context.Background(), "8.8.8.8")
			if err != nil || got.HeldReason != "unsafe_endpoint" || calls != 1 {
				t.Fatalf("unsafe bootstrap accepted %q: %+v %v calls=%d", endpoint, got, err, calls)
			}
		}
	})
	t.Run("redirects", func(t *testing.T) {
		for _, target := range []string{"http://rdap.db.ripe.net/ip/8.8.8.8", "https://evil.test/ip/8.8.8.8", "https://rdap.db.ripe.net/ip/9.9.9.9", "https://rdap.arin.net/other/ip/8.8.8.8", "https://rdap.db.ripe.net/ip/8.8.8.8?proxy=x", "https://rdap.db.ripe.net/ip/8.8.8.8"} {
			calls := 0
			r := fixtureResolver(t, func(req *http.Request) (*http.Response, error) {
				if req.URL.Host == "data.iana.org" {
					return response(200, bootstrapBody("8.8.8.8")), nil
				}
				calls++
				res := response(302, "")
				res.Header.Set("Location", target)
				return res, nil
			})
			got, err := r.lookup(context.Background(), "8.8.8.8")
			if err != nil || got.HeldReason != "unsafe_endpoint" || calls > 4 {
				t.Fatalf("unsafe redirect accepted %q: %+v %v calls=%d", target, got, err, calls)
			}
		}
	})
	t.Run("timeout_and_cancellation", func(t *testing.T) {
		r := fixtureResolver(t, func(req *http.Request) (*http.Response, error) {
			<-req.Context().Done()
			return nil, req.Context().Err()
		})
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel()
		_, err := r.lookup(ctx, "8.8.8.8")
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("cancellation not propagated: %v", err)
		}
	})
	t.Run("unsupported_fallback", func(t *testing.T) {
		r := fixtureResolver(t, func(req *http.Request) (*http.Response, error) {
			if req.URL.Host == "data.iana.org" {
				return response(200, bootstrapBody("1.1.1.1")), nil
			}
			return response(503, "secret"), nil
		})
		got, err := r.lookup(context.Background(), "1.1.1.1")
		if err != nil || got.HeldReason != "fallback_unsupported" {
			t.Fatalf("unsupported fallback: %+v %v", got, err)
		}
	})
}

func TestLookupWHOIS(t *testing.T) {
	for _, tc := range []struct{ name, body, wantHeld, wantEmail string }{
		{"narrow_abuse", "inetnum: 8.8.0.0 - 8.8.255.255\nabuse-mailbox: parent@example.net\n\ninetnum: 8.8.8.0 - 8.8.8.255\nabuse-mailbox: abuse@EXAMPLE.NET\nremarks: other@example.net\n", "", "abuse@example.net"},
		{"narrow_missing", "inetnum: 8.8.0.0 - 8.8.255.255\nabuse-mailbox: parent@example.net\n\ninetnum: 8.8.8.0 - 8.8.8.255\nremarks: fake@example.net\n", "contact_missing", ""},
		{"route_ignored", "route: 8.8.8.0/24\nabuse-mailbox: route@example.net\n", "invalid_response", ""},
		{"outside_range", "inetnum: 9.9.9.0 - 9.9.9.255\nabuse-mailbox: fake@example.net\n", "invalid_response", ""},
		{"unsafe_referral", "inetnum: 8.8.8.0 - 8.8.8.255\nabuse-mailbox: abuse@example.net\nrefer: whois://127.0.0.1:43\n", "unsafe_endpoint", ""},
		{"unsafe_referral_server", "inetnum: 8.8.8.0 - 8.8.8.255\nabuse-mailbox: abuse@example.net\nReferralServer: https://whois.ripe.net:443\n", "unsafe_endpoint", ""},
		{"self_referral", "inetnum: 8.8.8.0 - 8.8.8.255\nabuse-mailbox: abuse@example.net\nrefer: whois.ripe.net\n", "unsafe_endpoint", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := fixtureResolver(t, func(req *http.Request) (*http.Response, error) {
				if req.URL.Host == "data.iana.org" {
					return response(200, bootstrapBody("8.8.8.8")), nil
				}
				return response(503, "unavailable"), nil
			})
			r.whoisQuery = func(ctx context.Context, host, query string) (string, error) {
				if host != "whois.ripe.net" || query != "-b 8.8.8.8\r\n" {
					t.Errorf("wrong WHOIS query %q %q", host, query)
				}
				return tc.body, nil
			}
			got, err := r.lookup(context.Background(), "8.8.8.8")
			if err != nil || got.HeldReason != tc.wantHeld {
				t.Fatalf("WHOIS result: %+v %v", got, err)
			}
			if tc.wantEmail != "" && (len(got.Candidates) != 1 || got.Candidates[0].Email != tc.wantEmail || got.Method != "whois" || got.SourceURL != "whois://whois.ripe.net:43") {
				t.Errorf("WHOIS provenance/contact wrong: %+v", got)
			}
			if tc.wantHeld == "unsafe_endpoint" && len(got.Candidates) > 0 {
				t.Fatal("unsafe referral accepted partial contact")
			}
		})
	}
}

func TestLookupFailureMetadata(t *testing.T) {
	for _, test := range []struct {
		name       string
		status     int
		whoisError error
		reason     string
	}{
		{"supplement_unavailable", 200, errUnavailable, "registry_unavailable"},
		{"supplement_invalid", 200, errInvalid, "invalid_response"},
		{"long_retry_after", 429, nil, "rate_limited"},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := fixtureResolver(t, func(req *http.Request) (*http.Response, error) {
				if req.URL.Host == "data.iana.org" {
					return response(200, bootstrapBody("8.8.8.8")), nil
				}
				res := response(test.status, document(registryCase{Start: "8.8.8.0", End: "8.8.8.255", Version: "v4"}))
				res.Header.Set("Retry-After", "7200")
				return res, nil
			})
			r.whoisQuery = func(context.Context, string, string) (string, error) { return "", test.whoisError }
			got, err := r.lookup(context.Background(), "8.8.8.8")
			if err != nil || got.HeldReason != test.reason || got.LookupSucceeded || len(got.Candidates) != 0 {
				t.Fatalf("failure incorrectly marked complete: %+v %v", got, err)
			}
			if test.status == 429 {
				if got.ExpiresAt.Before(got.RetryAfter) {
					t.Fatal("failure expiry precedes Retry-After")
				}
			} else if got.ExpiresAt.Sub(got.QueriedAt) != time.Hour {
				t.Fatal("failed lookup cached for success TTL")
			}
		})
	}
}

func TestLookupBootstrapURLSelection(t *testing.T) {
	for _, tc := range []struct{ name, services, held string }{
		{"unordered_http_https", `[[["8.8.8.0/24"],["http://rdap.db.ripe.net/","https://rdap.db.ripe.net/"]]]`, ""},
		{"equal_prefix_conflict", `[[["8.8.8.0/24"],["https://rdap.db.ripe.net/"]],[["8.8.8.0/24"],["https://rdap.arin.net/registry/"]]]`, "invalid_response"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := fixtureResolver(t, func(req *http.Request) (*http.Response, error) {
				if req.URL.Host == "data.iana.org" {
					return response(200, `{"services":`+tc.services+`}`), nil
				}
				return response(200, document(registryCase{Start: "8.8.8.0", End: "8.8.8.255", Version: "v4", Emails: []string{"abuse@example.net"}, Roles: []string{"abuse"}})), nil
			})
			got, err := r.lookup(context.Background(), "8.8.8.8")
			if err != nil || got.HeldReason != tc.held {
				t.Fatalf("bootstrap selection: %+v %v", got, err)
			}
		})
	}
}

func TestLookupJSONContradictions(t *testing.T) {
	valid := document(registryCase{Start: "8.8.8.0", End: "8.8.8.255", Version: "v4", Emails: []string{"abuse@example.net"}, Roles: []string{"abuse"}})
	for _, body := range []string{
		strings.Replace(valid, `"startAddress":"8.8.8.0"`, `"StartAddress":"9.9.9.0","startAddress":"8.8.8.0"`, 1),
		strings.Replace(valid, `"roles":["abuse"]`, `"Roles":["technical"],"roles":["abuse"]`, 1),
		strings.Replace(valid, `"startAddress":"8.8.8.0"`, `"startAddress":"9.9.9.0","startAddress":"8.8.8.0"`, 1),
	} {
		r := fixtureResolver(t, func(req *http.Request) (*http.Response, error) {
			if req.URL.Host == "data.iana.org" {
				return response(200, bootstrapBody("8.8.8.8")), nil
			}
			return response(200, body), nil
		})
		got, err := r.lookup(context.Background(), "8.8.8.8")
		if err != nil || got.HeldReason != "invalid_response" || len(got.Candidates) > 0 {
			t.Fatalf("contradictory JSON accepted: %+v %v", got, err)
		}
	}
}

func TestLookupRedirectFallbackRegistry(t *testing.T) {
	for _, tc := range []struct {
		name, startHost, endHost string
		status                   int
		wantWhois                bool
		held                     string
	}{
		{"ripe_to_arin_missing", "rdap.db.ripe.net", "rdap.arin.net", 200, false, "contact_missing"},
		{"ripe_to_arin_unavailable", "rdap.db.ripe.net", "rdap.arin.net", 503, false, "fallback_unsupported"},
		{"arin_to_ripe_missing", "rdap.arin.net", "rdap.db.ripe.net", 200, true, ""},
		{"arin_to_ripe_unavailable", "rdap.arin.net", "rdap.db.ripe.net", 503, true, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := fixtureResolver(t, func(req *http.Request) (*http.Response, error) {
				if req.URL.Host == "data.iana.org" {
					return response(200, `{"services":[[["8.8.8.0/24"],["https://`+tc.startHost+rirBases[tc.startHost]+`"]]]}`), nil
				}
				if req.URL.Host == tc.startHost {
					res := response(302, "")
					res.Header.Set("Location", "https://"+tc.endHost+rirBases[tc.endHost]+"ip/8.8.8.8")
					return res, nil
				}
				return response(tc.status, document(registryCase{Start: "8.8.8.0", End: "8.8.8.255", Version: "v4"})), nil
			})
			whoisCalls := 0
			r.whoisQuery = func(context.Context, string, string) (string, error) {
				whoisCalls++
				return "inetnum: 8.8.8.0 - 8.8.8.255\nabuse-mailbox: abuse@example.net\n", nil
			}
			got, err := r.lookup(context.Background(), "8.8.8.8")
			if err != nil || got.HeldReason != tc.held || (whoisCalls > 0) != tc.wantWhois {
				t.Fatalf("wrong registry fallback: result=%+v err=%v whois=%d", got, err, whoisCalls)
			}
		})
	}
}

func TestLookupFallbackCannotBypassHeldResults(t *testing.T) {
	for _, tc := range []struct {
		name       string
		status     int
		body, held string
	}{
		{"rate_limit", 429, "", "rate_limited"},
		{"ambiguous", 200, document(registryCase{Start: "8.8.8.0", End: "8.8.8.255", Version: "v4", Emails: []string{"a@example.net", "b@example.net"}, Roles: []string{"abuse"}}), "contact_ambiguous"},
		{"invalid_contact", 200, document(registryCase{Start: "8.8.8.0", End: "8.8.8.255", Version: "v4", Emails: []string{"Name <abuse@example.net>"}, Roles: []string{"abuse"}}), "contact_invalid"},
		{"invalid_response", 200, "{", "invalid_response"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := fixtureResolver(t, func(req *http.Request) (*http.Response, error) {
				if req.URL.Host == "data.iana.org" {
					return response(200, bootstrapBody("8.8.8.8")), nil
				}
				return response(tc.status, tc.body), nil
			})
			r.whoisQuery = func(context.Context, string, string) (string, error) {
				t.Error("unsafe/ambiguous result bypassed by WHOIS")
				return "", errUnavailable
			}
			got, err := r.lookup(context.Background(), "8.8.8.8")
			if err != nil || got.HeldReason != tc.held {
				t.Fatalf("wrong held result %+v %v", got, err)
			}
		})
	}
}

func TestLookupWHOISResourceScope(t *testing.T) {
	for _, tc := range []struct{ name, body, method, held string }{
		{"broader_parent_contact", "inetnum: 8.8.0.0 - 8.8.255.255\nabuse-mailbox: parent@example.net\n", "rdap", "contact_missing"},
		{"narrower_contact", "inetnum: 8.8.8.8 - 8.8.8.8\nabuse-mailbox: specific@example.net\n", "whois", ""},
		{"equal_ambiguous", "inetnum: 8.8.8.0 - 8.8.8.255\nabuse-mailbox: a@example.net\nabuse-mailbox: b@example.net\n", "whois", "contact_ambiguous"},
		{"route_and_resource_mixed", "route: 8.8.8.0/24\nabuse-mailbox: route@example.net\ninetnum: 8.8.8.0 - 8.8.8.255\n", "rdap", "invalid_response"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := fixtureResolver(t, func(req *http.Request) (*http.Response, error) {
				if req.URL.Host == "data.iana.org" {
					return response(200, bootstrapBody("8.8.8.8")), nil
				}
				return response(200, document(registryCase{Start: "8.8.8.0", End: "8.8.8.255", Version: "v4"})), nil
			})
			r.whoisQuery = func(context.Context, string, string) (string, error) { return tc.body, nil }
			got, err := r.lookup(context.Background(), "8.8.8.8")
			if err != nil || got.HeldReason != tc.held || got.Method != tc.method {
				t.Fatalf("resource scope violated: %+v %v", got, err)
			}
		})
	}
}

func TestLookupRateLimitStopsOtherIPs(t *testing.T) {
	calls := 0
	r := fixtureResolver(t, func(req *http.Request) (*http.Response, error) {
		if req.URL.Host == "data.iana.org" {
			return response(200, bootstrapBody("8.8.8.8")), nil
		}
		calls++
		res := response(429, "")
		res.Header.Set("Retry-After", "120")
		return res, nil
	})
	r.whoisQuery = func(context.Context, string, string) (string, error) {
		t.Error("WHOIS bypassed HTTP rate limit")
		return "", errUnavailable
	}
	got, err := r.lookup(context.Background(), "8.8.8.8")
	if err != nil || got.HeldReason != "rate_limited" {
		t.Fatal("initial rate limit lost")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := r.lookup(ctx, "8.8.8.9"); !errors.Is(err, context.DeadlineExceeded) || calls != 1 {
		t.Fatalf("rate limit retried before deadline: calls=%d err=%v", calls, err)
	}
}

func TestLookupRedirectBound(t *testing.T) {
	hosts := []string{"rdap.db.ripe.net", "rdap.arin.net", "rdap.apnic.net", "rdap.afrinic.net", "rdap.lacnic.net"}
	for _, hops := range []int{3, 4} {
		t.Run(string(rune('0'+hops)), func(t *testing.T) {
			calls := 0
			r := fixtureResolver(t, func(req *http.Request) (*http.Response, error) {
				if req.URL.Host == "data.iana.org" {
					return response(200, bootstrapBody("8.8.8.8")), nil
				}
				deadline, ok := req.Context().Deadline()
				if !ok || time.Until(deadline) > requestTimeout {
					t.Error("unbounded request context")
				}
				index := calls
				calls++
				if index < hops {
					host := hosts[index+1]
					res := response(302, "")
					res.Header.Set("Location", "https://"+host+rirBases[host]+"ip/8.8.8.8")
					return res, nil
				}
				return response(200, document(registryCase{Start: "8.8.8.0", End: "8.8.8.255", Version: "v4", Emails: []string{"abuse@example.net"}, Roles: []string{"abuse"}})), nil
			})
			got, err := r.lookup(context.Background(), "8.8.8.8")
			if err != nil || calls != 4 || (hops == 3 && got.HeldReason != "") || (hops == 4 && got.HeldReason != "unsafe_endpoint") {
				t.Fatalf("redirect bound wrong calls=%d result=%+v err=%v", calls, got, err)
			}
		})
	}
}

func TestLookupJCardParameters(t *testing.T) {
	for _, parameters := range []string{"null", "[]", "7"} {
		doc := `{"objectClassName":"ip network","startAddress":"8.8.8.0","endAddress":"8.8.8.255","ipVersion":"v4","entities":[{"roles":["abuse"],"vcardArray":["vcard",[["email",` + parameters + `,"text","abuse@example.net"]]]}]}`
		r := fixtureResolver(t, func(req *http.Request) (*http.Response, error) {
			if req.URL.Host == "data.iana.org" {
				return response(200, bootstrapBody("8.8.8.8")), nil
			}
			return response(200, doc), nil
		})
		got, err := r.lookup(context.Background(), "8.8.8.8")
		if err != nil || got.HeldReason != "contact_invalid" || len(got.Candidates) != 0 {
			t.Fatalf("invalid jCard parameters accepted: %+v %v", got, err)
		}
	}
}

func TestLookupUnicodeFieldCollision(t *testing.T) {
	doc := `{"objectClassName":"ip network","startAddress":"8.8.8.0","endAddress":"8.8.8.255","ipVersion":"v4","entities":[{"roles":["technical"],"roleſ":["abuse"],"vcardArray":["vcard",[["email",{},"text","technical@example.net"]]]}]}`
	r := fixtureResolver(t, func(req *http.Request) (*http.Response, error) {
		if req.URL.Host == "data.iana.org" {
			return response(200, bootstrapBody("8.8.8.8")), nil
		}
		return response(200, doc), nil
	})
	got, err := r.lookup(context.Background(), "8.8.8.8")
	if err != nil || got.HeldReason != "invalid_response" || len(got.Candidates) != 0 {
		t.Fatalf("Unicode field collision changed role: %+v %v", got, err)
	}
}

func TestLookupMalformedJCardBlocksOtherValidCandidates(t *testing.T) {
	for _, tc := range []struct {
		name, properties string
		invalid          bool
	}{
		{"null_property_list", `null`, true},
		{"empty_property", `[[]]`, true},
		{"null_property", `[null]`, true},
		{"non_string_property_name", `[[7,{},"text","ignored"]]`, true},
		{"null_property_name", `[[null,{},"text","ignored"]]`, true},
		{"empty_property_name", `[["",{},"text","ignored"]]`, true},
		{"missing_property_value", `[["fn",{},"text"]]`, true},
		{"invalid_non_email_parameters", `[["fn",[],"text","ignored"]]`, true},
		{"null_non_email_parameters", `[["fn",null,"text","ignored"]]`, true},
		{"non_string_value_type", `[["fn",{},7,"ignored"]]`, true},
		{"empty_value_type", `[["fn",{},"","ignored"]]`, true},
		// Structural checks do not impose required vCard properties or collapse
		// non-email properties, whose values can occupy more than one array slot.
		{"empty_property_list", `[]`, false},
		{"valid_non_email_multiple_values", `[["categories",{},"text","operations","security"]]`, false},
		{"valid_non_email_structured_value", `[["adr",{},"text",["","","street","city","region","postal","country"]]]`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc := `{"objectClassName":"ip network","startAddress":"8.8.8.0","endAddress":"8.8.8.255","ipVersion":"v4","entities":[{"roles":["abuse"],"vcardArray":["vcard",` + tc.properties + `]},{"roles":["abuse"],"vcardArray":["vcard",[["email",{},"text","valid@example.net"]]]}]}`
			r := fixtureResolver(t, func(req *http.Request) (*http.Response, error) {
				if req.URL.Host == "data.iana.org" {
					return response(200, bootstrapBody("8.8.8.8")), nil
				}
				return response(200, doc), nil
			})
			r.whoisQuery = func(context.Context, string, string) (string, error) {
				t.Error("jCard validation bypassed by fallback")
				return "", errUnavailable
			}
			got, err := r.lookup(context.Background(), "8.8.8.8")
			wantHeld := ""
			if tc.invalid {
				wantHeld = "contact_invalid"
			}
			if err != nil || got.HeldReason != wantHeld || len(got.Candidates) != 1 || got.Candidates[0].Email != "valid@example.net" || !got.LookupSucceeded || got.ExpiresAt.Sub(got.QueriedAt) != 24*time.Hour {
				t.Fatalf("jCard structure/held result: %+v %v", got, err)
			}
		})
	}
}

func TestLookupMalformedWHOISResourceCannotSelectParent(t *testing.T) {
	for _, tc := range []struct {
		name, ip, parent, other string
		invalid                 bool
	}{
		{"reversed_ipv4", "8.8.8.8", "inetnum: 8.8.0.0 - 8.8.255.255", "inetnum: 8.8.8.9 - 8.8.8.1", true},
		{"invalid_start", "8.8.8.8", "inetnum: 8.8.0.0 - 8.8.255.255", "inetnum: invalid - 8.8.8.255", true},
		{"invalid_end", "8.8.8.8", "inetnum: 8.8.0.0 - 8.8.255.255", "inetnum: 8.8.8.0 - invalid", true},
		{"ipv6_in_inetnum", "8.8.8.8", "inetnum: 8.8.0.0 - 8.8.255.255", "inetnum: ::8 - ::9", true},
		{"mixed_family_in_inetnum", "8.8.8.8", "inetnum: 8.8.0.0 - 8.8.255.255", "inetnum: 8.8.8.0 - ::9", true},
		{"mapped_in_inetnum", "8.8.8.8", "inetnum: 8.8.0.0 - 8.8.255.255", "inetnum: ::ffff:8.8.8.0 - ::ffff:8.8.8.255", true},
		{"zone_in_inetnum", "8.8.8.8", "inetnum: 8.8.0.0 - 8.8.255.255", "inetnum: fe80::1%eth0 - fe80::2%eth0", true},
		{"ipv4_in_inet6num", "2a00:1450::1", "inet6num: 2a00::/12", "inet6num: 8.8.8.0/24", true},
		{"mapped_in_inet6num", "2a00:1450::1", "inet6num: 2a00::/12", "inet6num: ::ffff:8.8.8.0/120", true},
		{"zone_in_inet6num", "2a00:1450::1", "inet6num: 2a00::/12", "inet6num: 2a00:1450::%eth0/64", true},
		{"unrelated_valid_ipv4", "8.8.8.8", "inetnum: 8.8.0.0 - 8.8.255.255", "inetnum: 9.9.9.0 - 9.9.9.255", false},
		{"unrelated_valid_ipv6", "2a00:1450::1", "inet6num: 2a00::/12", "inet6num: 2606:4700::/32", false},
		{"valid_ipv6_object_on_ipv4_query", "8.8.8.8", "inetnum: 8.8.0.0 - 8.8.255.255", "inet6num: 2606:4700::/32", false},
		{"valid_ipv4_object_on_ipv6_query", "2a00:1450::1", "inet6num: 2a00::/12", "inetnum: 9.9.9.0 - 9.9.9.255", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, parentFirst := range []bool{true, false} {
				parent := tc.parent + "\nabuse-mailbox: parent@example.net\n"
				other := tc.other + "\nabuse-mailbox: other@example.net\n"
				body := parent + "\n" + other
				if !parentFirst {
					body = other + "\n" + parent
				}
				r := fixtureResolver(t, func(req *http.Request) (*http.Response, error) {
					if req.URL.Host == "data.iana.org" {
						return response(200, bootstrapBody(tc.ip)), nil
					}
					return response(503, "unavailable"), nil
				})
				r.whoisQuery = func(context.Context, string, string) (string, error) { return body, nil }
				got, err := r.lookup(context.Background(), tc.ip)
				if tc.invalid {
					if err != nil || got.HeldReason != "invalid_response" || got.LookupSucceeded || len(got.Candidates) != 0 {
						t.Fatalf("malformed resource selected parent, parentFirst=%t: %+v %v", parentFirst, got, err)
					}
				} else if err != nil || got.HeldReason != "" || !got.LookupSucceeded || len(got.Candidates) != 1 || got.Candidates[0].Email != "parent@example.net" {
					t.Fatalf("valid unrelated resource damaged result, parentFirst=%t: %+v %v", parentFirst, got, err)
				}
			}
		})
	}
}
