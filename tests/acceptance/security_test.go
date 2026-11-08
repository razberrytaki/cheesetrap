package acceptance

import (
	"slices"
	"testing"
	"time"

	"cheesetrap/internal/detection"
	"cheesetrap/internal/domain"
)

func TestSecurityInstallationSamplesCannotBecomeEligible(t *testing.T) {
	at := time.Now().UTC()
	var events []domain.Event
	for i := uint64(1); i <= 10; i++ {
		seq := i
		id := string(rune('a' + i))
		events = append(events, domain.Event{EventID: &id, IngestionSeq: &seq, ObservedAt: &at, IngestedAt: &at, Engine: "cowrie", Service: "ssh", EventType: "cowrie.login.failed", SourceIP: "1.1.1.1", DestinationIP: "8.8.8.8", DestinationPort: 2222, IsTest: true})
	}
	results, err := detection.Evaluate(events[len(events)-1], events)
	if err != nil || len(results) == 0 {
		t.Fatal("sample must actually reach attack threshold", err)
	}
	for _, result := range results {
		if result.EvidenceEligible || !slices.Contains(result.Explanation.HoldReasons, "test_evidence") {
			t.Fatal("installation sample accepted as draft evidence")
		}
	}
}
