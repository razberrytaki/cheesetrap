package api

import (
	"context"
	"encoding/json"
	"time"
)

type DetectionView struct {
	DetectionID            string          `json:"detection_id"`
	RuleID                 string          `json:"rule_id"`
	RuleVersion            string          `json:"rule_version"`
	SettingsVersion        string          `json:"settings_version"`
	SignatureID            string          `json:"signature_id"`
	SignatureVersion       string          `json:"signature_version"`
	ProcessingEventID      string          `json:"processing_event_id"`
	ProcessingIngestionSeq string          `json:"processing_ingestion_seq"`
	EvidenceCount          int             `json:"evidence_count"`
	EvidenceEligible       bool            `json:"evidence_eligible"`
	WindowStart            time.Time       `json:"window_start"`
	WindowEnd              time.Time       `json:"window_end"`
	Explanation            json.RawMessage `json:"explanation"`
	ExplanationTruncated   bool            `json:"explanation_truncated"`
}

func (s *server) ipDetections(ctx context.Context, ip string, limit int, rawCursor string) ([]DetectionView, string, error) {
	scope := pageScope("ip-detections", ip)
	snapshot, before, err := pageCursor(rawCursor, scope)
	if err != nil {
		return nil, "", err
	}
	rows, err := s.pool.Query(ctx, `SELECT detection_id::text,rule_id,rule_version,settings_version::text,signature_id,signature_version,processing_event_id::text,processing_ingestion_seq::text,evidence_count,evidence_eligible,window_start,window_end,CASE WHEN octet_length(explanation::text)<=65536 THEN explanation ELSE '{}'::jsonb END,octet_length(explanation::text)>65536,review_seq FROM cheesetrap.detection_results WHERE evidence_state='active' AND source_ip=$1 AND review_seq<=$2 AND review_seq<$3 ORDER BY review_seq DESC LIMIT $4`, ip, snapshot, before, limit+1)
	if err != nil {
		return nil, "", apiError(503)
	}
	defer rows.Close()
	result := []DetectionView{}
	next := ""
	var last int64
	for rows.Next() {
		var v DetectionView
		var seq int64
		if err = rows.Scan(&v.DetectionID, &v.RuleID, &v.RuleVersion, &v.SettingsVersion, &v.SignatureID, &v.SignatureVersion, &v.ProcessingEventID, &v.ProcessingIngestionSeq, &v.EvidenceCount, &v.EvidenceEligible, &v.WindowStart, &v.WindowEnd, &v.Explanation, &v.ExplanationTruncated, &seq); err != nil {
			return nil, "", apiError(503)
		}
		if len(result) == limit {
			next = encodePage(snapshot, last, scope)
			break
		}
		if len(result) == 0 && rawCursor == "" {
			snapshot = seq
		}
		result = append(result, v)
		last = seq
	}
	if rows.Err() != nil {
		return nil, "", apiError(503)
	}
	return result, next, nil
}
