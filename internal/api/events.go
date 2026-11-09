package api

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"strconv"
	"time"

	"cheesetrap/internal/observability"
	"cheesetrap/internal/store/db"
	"github.com/danielgtaylor/huma/v2"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

type Event struct {
	DetectionResult     string         `json:"detection_result" enum:"pending,no_match,evidence" doc:"As of the list detection snapshot: pending means not processed; no_match means processed without evidence membership, not benign; evidence means an actual detection evidence member, including copied historical proof"`
	ID                  string         `json:"event_id" format:"uuid"`
	Sequence            string         `json:"ingestion_seq" pattern:"^[1-9][0-9]*$" doc:"Lossless PostgreSQL bigint encoded as a decimal string"`
	Engine              string         `json:"engine"`
	ObservedAt          *time.Time     `json:"observed_at"`
	IngestedAt          time.Time      `json:"ingested_at"`
	SourceIP            *netip.Addr    `json:"source_ip"`
	SourcePort          *int32         `json:"source_port"`
	DestinationIP       *netip.Addr    `json:"destination_ip"`
	DestinationPort     *int32         `json:"destination_port"`
	Service             string         `json:"service"`
	Type                string         `json:"event_type"`
	SessionID           *string        `json:"session_id"`
	QualityFlags        []string       `json:"quality_flags"`
	IsTest              bool           `json:"is_test"`
	Attributes          map[string]any `json:"attributes" doc:"Normalized redacted evidence, treated as text; never HTML"`
	AttributesTruncated bool           `json:"attributes_truncated" doc:"Attributes over 16 KiB are omitted"`
}
type eventListInput struct {
	DetectionResult string `query:"detection_result" enum:"pending,no_match,evidence"`
	Limit           int    `query:"limit" default:"50" minimum:"1" maximum:"200"`
	Cursor          string `query:"cursor" maxLength:"512"`
	SourceIP        string `query:"source_ip" maxLength:"64"`
	Service         string `query:"service" maxLength:"64"`
	EventType       string `query:"event_type" maxLength:"128"`
	Since           string `query:"since" maxLength:"40" doc:"Inclusive ingested_at RFC3339 timestamp"`
	Until           string `query:"until" maxLength:"40" doc:"Exclusive ingested_at RFC3339 timestamp"`
	IsTest          string `query:"is_test" enum:"true,false"`
}
type eventListOutput struct {
	Body struct {
		Items      []Event `json:"items"`
		NextCursor string  `json:"next_cursor"`
	}
}
type eventInput struct {
	ID string `path:"id" format:"uuid"`
}
type eventOutput struct{ Body Event }
type overviewOutput struct {
	Body struct {
		Operations        observability.Status `json:"operations"`
		IngestedSequence  string               `json:"ingested_seq"`
		SensorsActive     string               `json:"sensors_active"`
		SensorsDegraded   string               `json:"sensors_degraded"`
		SensorsUnknown    string               `json:"sensors_unknown"`
		SensorsDisabled   string               `json:"sensors_disabled"`
		SensorsRecentGaps string               `json:"sensors_recent_gaps"`
		SensorsWithGaps   string               `json:"sensors_with_gaps"`
		DetectedSequence  string               `json:"detected_seq"`
	}
}
type cursor struct {
	Version  int    `json:"v"`
	Snapshot string `json:"snapshot"`
	Before   string `json:"before"`
	Filters  string `json:"filters"`
	Detected string `json:"detected,omitempty"`
	Epoch    string `json:"epoch,omitempty"`
}

func (s *server) registerEvents(a huma.API) {
	op := func(id, method, path string) huma.Operation {
		return huma.Operation{OperationID: id, Method: method, Path: path, Middlewares: huma.Middlewares{s.requireSession}, Errors: []int{400, 401, 403, 404, 409, 422, 503}, Security: []map[string][]string{{"session": {}}}}
	}
	huma.Register(a, op("events-list", "GET", "/api/v1/events"), s.listEvents)
	huma.Register(a, op("events-get", "GET", "/api/v1/events/{id}"), func(ctx context.Context, in *eventInput) (*eventOutput, error) {
		var id pgtype.UUID
		if id.Scan(in.ID) != nil || !id.Valid {
			return nil, apiError(400)
		}
		row, err := db.New(s.pool).GetAPIEvent(ctx, id)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apiError(404)
		}
		if err != nil {
			return nil, apiError(503)
		}
		return &eventOutput{Body: eventDTO(db.ListAPIEventsRow(row))}, nil
	})
	huma.Register(a, op("overview-get", "GET", "/api/v1/overview"), func(ctx context.Context, _ *struct{}) (*overviewOutput, error) {
		row, err := db.New(s.pool).GetAPIOverview(ctx)
		if err != nil {
			return nil, apiError(503)
		}
		operations, err := observability.Read(ctx, s.pool, time.Now())
		if err != nil {
			return nil, apiError(503)
		}
		out := &overviewOutput{}
		out.Body.Operations = operations
		out.Body.IngestedSequence = strconv.FormatInt(row.IngestedSeq, 10)
		out.Body.SensorsActive = strconv.FormatInt(row.SensorsActive, 10)
		out.Body.SensorsDegraded = strconv.FormatInt(row.SensorsDegraded, 10)
		out.Body.SensorsUnknown = strconv.FormatInt(row.SensorsUnknown, 10)
		out.Body.SensorsDisabled = strconv.FormatInt(row.SensorsDisabled, 10)
		out.Body.SensorsRecentGaps = strconv.FormatInt(row.SensorsRecentGaps, 10)
		out.Body.SensorsWithGaps = strconv.FormatInt(row.SensorsWithGaps, 10)
		out.Body.DetectedSequence = strconv.FormatInt(row.DetectedSeq, 10)
		return out, nil
	})
}
func (s *server) listEvents(ctx context.Context, in *eventListInput) (*eventListOutput, error) {
	p := db.ListAPIEventsParams{PageLimit: int32(in.Limit + 1)}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, apiError(503)
	}
	defer tx.Rollback(ctx)
	var epoch int64
	if err = tx.QueryRow(ctx, `SELECT coalesce((SELECT max(ingestion_seq) FROM cheesetrap.events),0),detected_seq,epoch FROM cheesetrap.processing_cursors,cheesetrap.event_list_state WHERE processing_cursors.singleton AND event_list_state.singleton`).Scan(&p.Snapshot, &p.DetectedSnapshot, &epoch); err != nil {
		return nil, apiError(503)
	}
	if in.DetectionResult != "" {
		p.DetectionResult = &in.DetectionResult
	}
	if in.SourceIP != "" {
		ip, err := netip.ParseAddr(in.SourceIP)
		if err != nil || ip.Zone() != "" {
			return nil, apiError(400)
		}
		ip = ip.Unmap()
		p.SourceIp = &ip
		in.SourceIP = ip.String()
	}
	if in.Service != "" {
		p.Service = &in.Service
	}
	if in.EventType != "" {
		p.EventType = &in.EventType
	}
	for _, item := range []struct {
		input  string
		target *pgtype.Timestamptz
	}{{in.Since, &p.Since}, {in.Until, &p.Until}} {
		if item.input != "" {
			value, err := time.Parse(time.RFC3339Nano, item.input)
			if err != nil {
				return nil, apiError(400)
			}
			*item.target = pgtype.Timestamptz{Time: value, Valid: true}
		}
	}
	if p.Since.Valid && p.Until.Valid && !p.Since.Time.Before(p.Until.Time) {
		return nil, apiError(400)
	}
	if in.IsTest != "" {
		value := in.IsTest == "true"
		p.IsTest = &value
	}
	filters := []string{in.SourceIP, in.Service, in.EventType, in.Since, in.Until, in.IsTest}
	legacyRaw, _ := json.Marshal(filters)
	legacySum := sha256.Sum256(legacyRaw)
	legacyFingerprint := hex.EncodeToString(legacySum[:])
	filters = append(filters, in.DetectionResult)
	raw, _ := json.Marshal(filters)
	sum := sha256.Sum256(raw)
	fingerprint := hex.EncodeToString(sum[:])
	if in.Cursor != "" {
		var c cursor
		raw, err := base64.RawURLEncoding.DecodeString(in.Cursor)
		if err != nil || json.Unmarshal(raw, &c) != nil || (c.Version != 1 && c.Version != 2) {
			return nil, apiError(400)
		}
		if c.Version == 1 {
			if in.DetectionResult != "" || c.Filters != legacyFingerprint {
				return nil, apiError(400)
			}
		} else {
			if c.Filters != fingerprint {
				return nil, apiError(400)
			}
			processed, e1 := strconv.ParseInt(c.Detected, 10, 64)
			savedEpoch, e2 := strconv.ParseInt(c.Epoch, 10, 64)
			if e1 != nil || e2 != nil || processed < 0 || savedEpoch < 0 || strconv.FormatInt(processed, 10) != c.Detected || strconv.FormatInt(savedEpoch, 10) != c.Epoch || processed > p.DetectedSnapshot {
				return nil, apiError(400)
			}
			if savedEpoch != epoch {
				return nil, apiError(409)
			}
			p.DetectedSnapshot = processed
		}
		snapshot, err1 := strconv.ParseInt(c.Snapshot, 10, 64)
		before, err2 := strconv.ParseInt(c.Before, 10, 64)
		if err1 != nil || err2 != nil || snapshot < 1 || before < 1 || before > snapshot || strconv.FormatInt(snapshot, 10) != c.Snapshot || strconv.FormatInt(before, 10) != c.Before {
			return nil, apiError(400)
		}
		p.Snapshot = snapshot
		p.BeforeSeq = &before
	}
	var rows []db.ListAPIEventsRow
	if in.DetectionResult == "pending" {
		// Keep the sequence lower bound in a dedicated query: an optional OR
		// predicate can hide it from a generic prepared plan.
		pending, queryErr := db.New(tx).ListAPIPendingEvents(ctx, db.ListAPIPendingEventsParams{
			DetectedSnapshot: p.DetectedSnapshot, Snapshot: p.Snapshot, BeforeSeq: p.BeforeSeq,
			SourceIp: p.SourceIp, Service: p.Service, EventType: p.EventType, Since: p.Since, Until: p.Until, IsTest: p.IsTest, PageLimit: p.PageLimit,
		})
		err = queryErr
		rows = make([]db.ListAPIEventsRow, len(pending))
		for i, row := range pending {
			rows[i] = db.ListAPIEventsRow(row)
		}
	} else {
		rows, err = db.New(tx).ListAPIEvents(ctx, p)
	}
	if err != nil {
		return nil, apiError(503)
	}
	out := &eventListOutput{}
	out.Body.Items = make([]Event, 0, min(len(rows), in.Limit))
	if in.Cursor == "" && len(rows) > 0 {
		p.Snapshot = rows[0].IngestionSeq
	}
	more := len(rows) > in.Limit
	if more {
		rows = rows[:in.Limit]
	}
	for _, row := range rows {
		out.Body.Items = append(out.Body.Items, eventDTO(row))
	}
	if more {
		c := cursor{Version: 2, Detected: strconv.FormatInt(p.DetectedSnapshot, 10), Epoch: strconv.FormatInt(epoch, 10), Snapshot: strconv.FormatInt(p.Snapshot, 10), Before: strconv.FormatInt(rows[len(rows)-1].IngestionSeq, 10), Filters: fingerprint}
		raw, _ := json.Marshal(c)
		out.Body.NextCursor = base64.RawURLEncoding.EncodeToString(raw)
	}
	return out, nil
}
func eventDTO(row db.ListAPIEventsRow) Event {
	var observed *time.Time
	if row.ObservedAt.Valid {
		observed = &row.ObservedAt.Time
	}
	attrs := map[string]any{}
	_ = json.Unmarshal(row.Attributes, &attrs)
	flags := row.QualityFlags
	if flags == nil {
		flags = []string{}
	}
	return Event{DetectionResult: row.DetectionResult, ID: row.EventID.String(), Sequence: strconv.FormatInt(row.IngestionSeq, 10), Engine: row.Engine, ObservedAt: observed, IngestedAt: row.IngestedAt.Time, SourceIP: row.SourceIp, SourcePort: row.SourcePort, DestinationIP: row.DestinationIp, DestinationPort: row.DestinationPort, Service: row.Service, Type: row.EventType, SessionID: row.SessionID, QualityFlags: flags, IsTest: row.IsTest, Attributes: attrs, AttributesTruncated: row.AttributesTruncated}
}
