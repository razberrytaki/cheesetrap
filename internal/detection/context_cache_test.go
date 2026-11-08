package detection

import (
	"context"
	"encoding/json"
	"net/netip"
	"testing"
	"time"

	"cheesetrap/internal/domain"
	"cheesetrap/internal/store/db"
	"github.com/jackc/pgx/v5/pgtype"
)

func cacheTestRows(events []domain.Event) []db.CheesetrapEvent {
	rows := make([]db.CheesetrapEvent, len(events))
	for i, e := range events {
		var id pgtype.UUID
		_ = id.Scan(*e.EventID)
		ip := netip.MustParseAddr(e.SourceIP)
		destination := netip.MustParseAddr(e.DestinationIP)
		port := int32(e.DestinationPort)
		attrs, _ := json.Marshal(e.Attributes)
		rows[i] = db.CheesetrapEvent{EventID: id, IngestionSeq: int64(*e.IngestionSeq), ObservedAt: timestamp(*e.ObservedAt), IngestedAt: timestamp(*e.IngestedAt), SourceIp: &ip, DestinationIp: &destination, DestinationPort: &port, Engine: e.Engine, Service: e.Service, EventType: e.EventType, Attributes: attrs, QualityFlags: e.QualityFlags, IsTest: e.IsTest}
	}
	return rows
}

func TestContextCacheExactWindowAndLazyConversion(t *testing.T) {
	events := fixtureEvents(ruleFixture{Groups: []fixtureGroup{{Count: 1}, {Count: 1, Start: 600}, {Count: 1, Start: 1800}, {Count: 1, Start: 600}, {Count: 1, Start: 1200}}})
	rows := cacheTestRows(events)
	calls, converted := 0, map[int64]int{}
	c := newDetectionContextCache(rows[3:], defaultContextCacheLimits(), func(_ context.Context, p db.ListDetectionContextParams) ([]db.CheesetrapEvent, error) {
		calls++
		if !p.WindowStart.Time.Equal(*events[0].ObservedAt) || !p.WindowEnd.Time.Equal(*events[2].ObservedAt) || p.ProcessingSeq != 4 {
			t.Fatalf("incorrect complete envelope: %+v", p)
		}
		return rows[:3], nil
	}, func(row db.CheesetrapEvent) (domain.Event, error) {
		converted[row.IngestionSeq]++
		return domainEvent(row)
	})
	first, err := c.history(context.Background(), events[3])
	if err != nil || len(first) != 2 || converted[3] != 0 {
		t.Fatalf("overfetched row converted early: %d %+v %v", len(first), converted, err)
	}
	c.completed(rows[3], events[3])
	second, err := c.history(context.Background(), events[4])
	if err != nil || len(second) != 3 || calls != 1 || converted[1] != 1 || converted[2] != 1 || converted[3] != 1 {
		t.Fatalf("cache lost exact-boundary evidence or decoded twice: %d calls=%d converted=%v err=%v", len(second), calls, converted, err)
	}
}

func TestContextCacheFallbackNeverTruncates(t *testing.T) {
	for _, tc := range []struct {
		name   string
		limits contextCacheLimits
	}{
		{"disabled", contextCacheLimits{}},
		{"row_admission", contextCacheLimits{keys: 1, rows: 2, span: Window}},
		{"row_append", contextCacheLimits{keys: 1, rows: 3, span: Window}},
		{"wide_span", contextCacheLimits{keys: 1, rows: 10, span: time.Second}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			events := fixtureEvents(ruleFixture{Groups: []fixtureGroup{{Count: 3, Start: 600}, {Count: 1, Start: 600}, {Count: 1, Start: 1200}}})
			rows := cacheTestRows(events)
			calls := 0
			completed := rows[:3]
			c := newDetectionContextCache(rows[3:], tc.limits, func(_ context.Context, p db.ListDetectionContextParams) ([]db.CheesetrapEvent, error) {
				calls++
				return completed, nil
			}, domainEvent)
			first, err := c.history(context.Background(), events[3])
			if err != nil || len(first) != 3 {
				t.Fatalf("initial full evidence lost: %d %v", len(first), err)
			}
			completed = rows[:4]
			c.completed(rows[3], events[3])
			second, err := c.history(context.Background(), events[4])
			if err != nil || len(second) != 4 || calls != 2 || c.retained != 0 {
				t.Fatalf("fallback truncated: %d calls=%d retained=%d err=%v", len(second), calls, c.retained, err)
			}
		})
	}
}

func TestContextCacheKeyLimit(t *testing.T) {
	events := fixtureEvents(ruleFixture{Groups: []fixtureGroup{{Count: 1}, {Count: 2, IP: "198.51.100.21"}}})
	rows := cacheTestRows(events)
	calls := 0
	c := newDetectionContextCache(rows, contextCacheLimits{keys: 1, rows: 10, span: Window}, func(context.Context, db.ListDetectionContextParams) ([]db.CheesetrapEvent, error) {
		calls++
		return nil, nil
	}, domainEvent)
	for _, e := range events {
		if _, err := c.history(context.Background(), e); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 3 || len(c.entries) != 1 {
		t.Fatalf("key cap exceeded: calls=%d entries=%d", calls, len(c.entries))
	}
}

func TestContextCachePreservesEveryRuleResult(t *testing.T) {
	for _, tc := range []struct {
		name, kind string
		paths      []string
		count      int
	}{
		{"SSH-REPEAT", "", nil, 10}, {"WEB-REPEAT", "web", SuspiciousPaths(), 20}, {"WEB-EXPLOIT", "web", []string{"/../etc/passwd"}, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			events := fixtureEvents(ruleFixture{Groups: []fixtureGroup{{Count: 3, Kind: "normal"}, {Count: tc.count - 1, Kind: tc.kind, Paths: tc.paths, Start: 60, Step: 20, Flags: []string{"collection_gap"}}, {Count: 1, Kind: tc.kind, Paths: tc.paths}}})
			for i := range events {
				if events[i].Service == "http" && i%2 == 0 {
					events[i].Service = "https"
				}
			}
			rows := cacheTestRows(events)
			for _, limits := range []contextCacheLimits{defaultContextCacheLimits(), {keys: 1, rows: 1, span: Window}} {
				c := newDetectionContextCache(rows, limits, func(_ context.Context, p db.ListDetectionContextParams) ([]db.CheesetrapEvent, error) {
					out := []db.CheesetrapEvent{}
					for _, r := range rows {
						if r.IngestionSeq < p.ProcessingSeq && r.EventType == p.EventType && !r.ObservedAt.Time.Before(p.WindowStart.Time) && !r.ObservedAt.Time.After(p.WindowEnd.Time) {
							out = append(out, r)
						}
					}
					return out, nil
				}, domainEvent)
				for i, e := range events {
					history := []domain.Event{}
					if triggerNeedsContext(DefaultConfig(), e) {
						var err error
						history, err = c.history(context.Background(), e)
						if err != nil {
							t.Fatal(err)
						}
					}
					got, err := EvaluateConfigured(e, history, DefaultConfig(), 2)
					if err != nil {
						t.Fatal(err)
					}
					want, err := EvaluateConfigured(e, events[:i], DefaultConfig(), 2)
					if err != nil {
						t.Fatal(err)
					}
					a, _ := json.Marshal(got)
					b, _ := json.Marshal(want)
					if string(a) != string(b) {
						t.Fatalf("cached result differs at seq %d: %s vs %s", i+1, a, b)
					}
					if i == len(events)-1 && (len(got) != 1 || got[0].RuleID != tc.name) {
						t.Fatal("fixture did not exercise expected rule")
					}
					c.completed(rows[i], e)
				}
			}
		})
	}
}
