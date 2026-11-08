package retention

import (
	"testing"
	"time"
)

func TestRetentionPolicy(t *testing.T) {
	p := DefaultPolicy()
	if p.RawDays != 7 || p.RawBytes != "1073741824" || p.EventDays != 30 || p.HistoryDays != 180 || p.JobDays != 7 {
		t.Fatalf("policy: %+v", p)
	}
	now := time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)
	for _, state := range []string{"preparing", "held", "needs_review", "queued", "sending", "retry_wait", "unknown", "failed", "cancelled"} {
		if TerminalExpired(state, now.Add(-181*24*time.Hour), false, now) {
			t.Fatal(state)
		}
	}
	for _, state := range []string{"sent", "rejected", "closed_unconfirmed"} {
		if !TerminalExpired(state, now.Add(-181*24*time.Hour), false, now) {
			t.Fatal(state)
		}
		if TerminalExpired(state, now.Add(-180*24*time.Hour), false, now) {
			t.Fatal("boundary")
		}
	}
	if TerminalExpired("sent", now.Add(-181*24*time.Hour), true, now) {
		t.Fatal("unresolved uncertainty")
	}
	if !TerminalExpired("closed_unconfirmed", now.Add(-181*24*time.Hour), true, now) {
		t.Fatal("resolved uncertainty")
	}
}
