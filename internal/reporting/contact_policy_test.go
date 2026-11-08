package reporting

import (
	"cheesetrap/internal/enrichment"
	"testing"
)

func TestDraftContactProvenance(t *testing.T) {
	for _, tc := range []struct {
		method, sourceURL string
		accepted          bool
	}{
		{"whois", "whois://whois.example.net/1.1.1.1", true},
		{"rdap", "https://rdap.example.net/ip/1.1.1.1", true},
		{"unknown", "https://rdap.example.net/ip/1.1.1.1", false},
	} {
		t.Run(tc.method, func(t *testing.T) {
			registry := enrichment.Result{Address: "1.1.1.1", LookupSucceeded: true, Candidates: []enrichment.Contact{{Email: "abuse@example.net", Role: "abuse", Sources: []enrichment.Source{{Role: "abuse", Method: tc.method, SourceURL: tc.sourceURL, NetworkStart: "1.1.1.0", NetworkEnd: "1.1.1.255"}}}}}
			contacts := verifiedContacts(registry, "1.1.1.1")
			if contacts["abuse@example.net"] != tc.accepted {
				t.Fatal("contact provenance changed")
			}
			if contacts["other@example.net"] || len(verifiedContacts(registry, "8.8.8.8")) != 0 {
				t.Fatal("unrelated contact or address accepted")
			}
		})
	}
}
