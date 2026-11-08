package reporting

import (
	"context"
	"encoding/json"
	"net/netip"
	"sort"
	"strconv"
	"time"

	"cheesetrap/internal/domain"
	"cheesetrap/internal/store/db"

	"github.com/jackc/pgx/v5/pgtype"
)

// collectEvidence runs under the draft lock. One event is assigned globally;
// rule context remains independently counted even when older context is owned.
func collectEvidence(ctx context.Context, q *db.Queries, w db.CheesetrapReportWindow, source string) (domain.ReportSnapshot, error) {
	snapshot := domain.ReportSnapshot{SourceIP: source, WindowID: w.WindowID.String(), WindowStart: w.StartAt.Time.UTC(), WindowEnd: w.EndAt.Time.UTC(), Evidence: []domain.ReportEvidence{}, Rules: []domain.ReportRule{}}
	detections, err := q.ListReportSourceDetections(ctx, db.ListReportSourceDetectionsParams{WindowID: w.WindowID, SourceIp: netip.MustParseAddr(source)})
	if err != nil {
		return snapshot, err
	}

	for _, d := range detections {
		snapshot.Rules = append(snapshot.Rules, domain.ReportRule{SettingsVersion: strconv.FormatInt(d.SettingsVersion, 10), DetectionID: d.DetectionID.String(), RuleID: d.RuleID, RuleVersion: d.RuleVersion, SignatureID: d.SignatureID, SignatureVersion: d.SignatureVersion, ContextCount: int(d.EvidenceCount), AttachedCount: int(d.AttachedCount), EvidenceHash: d.EvidenceHash, EvidenceEligible: d.EvidenceEligible, AutoApprovalAllowed: d.AutoApprovalAllowed, Explanation: d.Explanation})
	}
	rows, err := q.ListReportCandidateEvidence(ctx, db.ListReportCandidateEvidenceParams{WindowID: w.WindowID, SourceIp: netip.MustParseAddr(source)})
	if err != nil {
		return snapshot, err
	}
	sensorIDs := []pgtype.UUID{}
	seen := map[pgtype.UUID]bool{}
	for _, row := range rows {
		if !seen[row.SensorID] {
			seen[row.SensorID] = true
			sensorIDs = append(sensorIDs, row.SensorID)
		}
	}
	gaps, err := q.ReportEvidenceGaps(ctx, sensorIDs)
	if err != nil {
		return snapshot, err
	}
	bySensor := map[pgtype.UUID]json.RawMessage{}
	for _, gap := range gaps {
		data, err := json.Marshal(struct {
			StartedAt       time.Time `json:"started_at"`
			ObservedThrough time.Time `json:"observed_through"`
		}{gap.StartedAt.Time.UTC(), gap.ObservedThrough.Time.UTC()})
		if err != nil {
			return snapshot, err
		}
		bySensor[gap.SensorID] = data
	}
	for _, row := range rows {
		e, err := copyEvidence(db.CheesetrapEvent(row))
		if err != nil {
			return snapshot, err
		}
		e.CollectionGap = bySensor[row.SensorID]
		snapshot.Evidence = append(snapshot.Evidence, e)
	}
	sort.Slice(snapshot.Evidence, func(i, j int) bool { return snapshot.Evidence[i].IngestionSeq < snapshot.Evidence[j].IngestionSeq })
	for _, e := range snapshot.Evidence {
		if !e.ObservedAt.IsZero() {
			if snapshot.ObservedStart.IsZero() || e.ObservedAt.Before(snapshot.ObservedStart) {
				snapshot.ObservedStart = e.ObservedAt
			}
			if snapshot.ObservedEnd.IsZero() || e.ObservedAt.After(snapshot.ObservedEnd) {
				snapshot.ObservedEnd = e.ObservedAt
			}
		}
		if e.ObservedAt.Before(snapshot.WindowStart) {
			snapshot.DelayedCollection = true
		}
	}
	return snapshot, nil
}
func copyEvidence(row db.CheesetrapEvent) (domain.ReportEvidence, error) {
	e := domain.ReportEvidence{EventID: row.EventID.String(), IngestionSeq: row.IngestionSeq, SensorID: row.SensorID.String(), Engine: row.Engine, IngestedAt: row.IngestedAt.Time.UTC(), Service: row.Service, EventType: row.EventType, RawHash: row.RawHash, QualityFlags: row.QualityFlags, IsTest: row.IsTest}
	if row.ObservedAt.Valid {
		e.ObservedAt = row.ObservedAt.Time.UTC()
	}
	if row.SourceIp != nil {
		e.SourceIP = row.SourceIp.Unmap().String()
	}
	if row.SourcePort != nil {
		e.SourcePort = int(*row.SourcePort)
	}
	// The adapter's destination is the configured public endpoint, not an
	// engine's container address. Reject a non-public destination again here.
	if row.DestinationIp != nil {
		e.DestinationIP = row.DestinationIp.Unmap().String()
	}
	if row.DestinationPort != nil {
		e.DestinationPort = int(*row.DestinationPort)
	}
	var attributes domain.Attributes
	if json.Unmarshal(row.Attributes, &attributes) != nil {
		return e, ErrRevisionFailed
	}
	if attributes.Method != nil {
		e.Method = plain(*attributes.Method)
	}
	if attributes.URI != nil {
		e.URI = plain(*attributes.URI)
	}
	if attributes.Command != nil {
		e.Command = plain(*attributes.Command)
	}
	// No username/password/body/header/session payload crosses this allowlist.
	e.FieldCompleteness = attributes.FieldCompleteness
	e.Truncation = attributes.Truncation
	return e, nil
}
