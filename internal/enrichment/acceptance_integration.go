//go:build integration

package enrichment

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
)

// AcceptanceRegistry uses the real bootstrap, RDAP parser and contact policy,
// but a closed transport with exactly two responses. It cannot dial a network.
// It is absent from production and release builds without the integration tag.
type AcceptanceRegistry struct{ Calls int }
type acceptanceTransport func(*http.Request) (*http.Response, error)

func (f acceptanceTransport) RoundTrip(q *http.Request) (*http.Response, error) { return f(q) }
func (a *AcceptanceRegistry) Lookup(ctx context.Context, address string) (Result, error) {
	if address != "1.1.1.1" {
		return held(address, "address_not_public"), nil
	}
	r := newResolver()
	r.gate = newHostGate(0)
	r.client = &http.Client{Transport: acceptanceTransport(func(q *http.Request) (*http.Response, error) {
		a.Calls++
		body := ""
		switch q.URL.String() {
		case "https://data.iana.org/rdap/ipv4.json":
			body = `{"services":[[["1.1.1.0/24"],["https://rdap.arin.net/registry/"]]]}`
		case "https://rdap.arin.net/registry/ip/1.1.1.1":
			body = `{"objectClassName":"ip network","startAddress":"1.1.1.0","endAddress":"1.1.1.255","ipVersion":"v4","entities":[{"roles":["abuse"],"vcardArray":["vcard",[["email",{},"text","first@example.test"]]]},{"roles":["abuse"],"vcardArray":["vcard",[["email",{},"text","second@example.test"]]]}]}`
		default:
			return nil, errors.New("unexpected acceptance registry request")
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
	}), CheckRedirect: r.checkRedirect}
	r.whoisQuery = func(context.Context, string, string) (string, error) { return "", errors.New("unexpected WHOIS") }
	return r.lookup(ctx, address)
}
