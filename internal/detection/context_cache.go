package detection

import (
	"context"
	"net/netip"
	"time"

	"cheesetrap/internal/domain"
	"cheesetrap/internal/store/db"
)

type contextCacheLimits struct {
	keys, rows int
	span       time.Duration
}

func defaultContextCacheLimits() contextCacheLimits {
	return contextCacheLimits{keys: 32, rows: 32768, span: Window}
}

type contextKey struct{ source, eventType string }
type contextEnvelope struct{ start, end time.Time }
type cachedContextRow struct {
	row     db.CheesetrapEvent
	decoded *domain.Event
}
type detectionContextCache struct {
	limits    contextCacheLimits
	envelopes map[contextKey]contextEnvelope
	entries   map[contextKey][]cachedContextRow
	disabled  map[contextKey]bool
	retained  int
	load      func(context.Context, db.ListDetectionContextParams) ([]db.CheesetrapEvent, error)
	convert   func(db.CheesetrapEvent) (domain.Event, error)
}

// The cache lives only while the cursor-locked transaction is open. Envelopes
// describe this batch, but loads include only completed, lower-sequence events.
func newDetectionContextCache(rows []db.CheesetrapEvent, limits contextCacheLimits, load func(context.Context, db.ListDetectionContextParams) ([]db.CheesetrapEvent, error), convert func(db.CheesetrapEvent) (domain.Event, error)) *detectionContextCache {
	c := &detectionContextCache{limits: limits, envelopes: map[contextKey]contextEnvelope{}, entries: map[contextKey][]cachedContextRow{}, disabled: map[contextKey]bool{}, load: load, convert: convert}
	if limits.keys <= 0 || limits.rows <= 0 {
		return c
	}
	for _, row := range rows {
		if row.SourceIp == nil || !row.ObservedAt.Valid {
			continue
		}
		key := contextKey{row.SourceIp.Unmap().String(), row.EventType}
		at := row.ObservedAt.Time
		envelope, exists := c.envelopes[key]
		if !exists {
			envelope = contextEnvelope{at, at}
		}
		if at.Before(envelope.start) {
			envelope.start = at
		}
		if at.After(envelope.end) {
			envelope.end = at
		}
		c.envelopes[key] = envelope
	}
	return c
}

func (c *detectionContextCache) history(ctx context.Context, trigger domain.Event) ([]domain.Event, error) {
	ip, _ := sourceIP(trigger)
	key := contextKey{ip, trigger.EventType}
	start, end := trigger.ObservedAt.Add(-Window), trigger.ObservedAt.Add(Window)
	if rows, exists := c.entries[key]; exists {
		return c.selectHistory(rows, trigger, start, end)
	}
	envelope, planned := c.envelopes[key]
	admit := planned && !c.disabled[key] && len(c.entries) < c.limits.keys && envelope.end.Sub(envelope.start) <= c.limits.span
	queryStart, queryEnd := start, end
	if admit {
		queryStart, queryEnd = envelope.start.Add(-Window), envelope.end.Add(Window)
	}
	rows, err := c.load(ctx, db.ListDetectionContextParams{SourceIp: netip.MustParseAddr(ip), EventType: trigger.EventType, ProcessingSeq: int64(*trigger.IngestionSeq), WindowStart: timestamp(queryStart), WindowEnd: timestamp(queryEnd)})
	if err != nil {
		return nil, err
	}
	cached := make([]cachedContextRow, len(rows))
	for i, row := range rows {
		cached[i].row = row
	}
	// Never truncate an oversized load. Use it for this trigger, then fall back to
	// complete exact-window queries for the rest of this transaction.
	if admit && len(rows) <= c.limits.rows-c.retained {
		c.entries[key] = cached
		c.retained += len(rows)
	} else if admit {
		c.disabled[key] = true
	}
	return c.selectHistory(cached, trigger, start, end)
}

func (c *detectionContextCache) selectHistory(rows []cachedContextRow, trigger domain.Event, start, end time.Time) ([]domain.Event, error) {
	history := []domain.Event{}
	for i := range rows {
		row := &rows[i]
		if !row.row.ObservedAt.Valid || row.row.ObservedAt.Time.Before(start) || row.row.ObservedAt.Time.After(end) || row.row.IngestionSeq >= int64(*trigger.IngestionSeq) {
			continue
		}
		// Convert only evidence in the current exact window. Overfetched rows must
		// not cause early conversion failures or sensor-gap lookups.
		if row.decoded == nil {
			e, err := c.convert(row.row)
			if err != nil {
				return nil, err
			}
			row.decoded = &e
		}
		history = append(history, *row.decoded)
	}
	return history, nil
}

// Call only after the completion insert succeeds, including for nonmatches.
func (c *detectionContextCache) completed(row db.CheesetrapEvent, event domain.Event) {
	ip, valid := sourceIP(event)
	if !valid || event.ObservedAt == nil {
		return
	}
	key := contextKey{ip, event.EventType}
	rows, exists := c.entries[key]
	if !exists {
		return
	}
	if c.retained >= c.limits.rows {
		c.retained -= len(rows)
		delete(c.entries, key)
		c.disabled[key] = true
		return
	}
	c.entries[key] = append(rows, cachedContextRow{row: row, decoded: &event})
	c.retained++
}
