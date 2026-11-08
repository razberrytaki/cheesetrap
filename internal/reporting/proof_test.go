package reporting

import (
	"cheesetrap/internal/domain"
	"fmt"
	"strings"
	"testing"
)

type generatedContents struct{ n int }

func (g generatedContents) Counts() (int, int)       { return g.n, g.n }
func (g generatedContents) NullArrays() (bool, bool) { return false, false }
func (g generatedContents) EachEvidence(f func(domain.ReportEvidence) error) error {
	for i := 0; i < g.n; i++ {
		if err := f(domain.ReportEvidence{EventID: fmt.Sprint(i), Service: "ssh", DestinationIP: "8.8.8.8", DestinationPort: i%65535 + 1}); err != nil {
			return err
		}
	}
	return nil
}
func (g generatedContents) EachRule(f func(domain.ReportRule) error) error {
	for i := 0; i < g.n; i++ {
		if err := f(domain.ReportRule{RuleID: "SSH-REPEAT", RuleVersion: "1", SettingsVersion: fmt.Sprint(i), ContextCount: 10}); err != nil {
			return err
		}
	}
	return nil
}
func TestRenderSummaryBudgetPreservesTotal(t *testing.T) {
	r := domain.ReportRevision{ReportID: "summary-budget", Snapshot: domain.ReportSnapshot{SourceIP: "1.1.1.1", Contents: generatedContents{40000}}}
	_, body, err := Render(r)
	if err != nil || !ValidBody(body) || !strings.Contains(body, "Some destination endpoints were omitted") || !strings.Contains(body, "Evidence records: 40000") {
		t.Fatal("bounded summary", len(body), err)
	}
}

// Small fixtures only. Production consumers must use the bounded iterators.
func materializeRevisionForTest(t *testing.T, r domain.ReportRevision) domain.ReportRevision {
	t.Helper()
	var evidence []domain.ReportEvidence
	var rules []domain.ReportRule
	if err := r.Snapshot.EachEvidence(func(e domain.ReportEvidence) error { evidence = append(evidence, e); return nil }); err != nil {
		t.Fatal(err)
	}
	if err := r.Snapshot.EachRule(func(rule domain.ReportRule) error { rules = append(rules, rule); return nil }); err != nil {
		t.Fatal(err)
	}
	r.Snapshot.Evidence = evidence
	r.Snapshot.Rules = rules
	r.Snapshot.Contents = nil
	r.Snapshot.Proof = nil
	return r
}
