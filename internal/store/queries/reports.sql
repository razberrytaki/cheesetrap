-- Stable membership is attributed to the detection's processing trigger, not
-- its observed-time evidence range. Readiness proves all triggers were processed.
-- name: ListWindowDetections :many
SELECT d.* FROM cheesetrap.report_windows w
JOIN cheesetrap.events e ON e.ingested_at>=w.start_at AND e.ingested_at<w.end_at AND e.ingestion_seq<=w.sealed_seq
JOIN cheesetrap.detection_results d ON d.processing_event_id=e.event_id AND d.processing_ingestion_seq=e.ingestion_seq
WHERE w.window_id=$1 AND w.state='ready' AND d.evidence_state='active'
ORDER BY d.processing_ingestion_seq,d.detection_id;

-- name: LockReportDrafts :one
SELECT singleton FROM cheesetrap.report_draft_lock WHERE singleton FOR UPDATE;

-- Earliest unfinished window includes sealed/open windows: later ready windows
-- cannot win evidence ownership while an earlier window still needs detection.
-- name: NextDraftWindow :one
SELECT w.* FROM cheesetrap.report_windows w WHERE NOT EXISTS(SELECT 1 FROM cheesetrap.report_window_completions c WHERE c.window_id=w.window_id) ORDER BY w.start_at LIMIT 1;

-- name: NextDraftSource :one
SELECT host(d.source_ip)::text AS source_ip FROM cheesetrap.report_windows w
JOIN cheesetrap.events e ON e.ingested_at>=w.start_at AND e.ingested_at<w.end_at AND e.ingestion_seq<=w.sealed_seq
JOIN cheesetrap.detection_results d ON d.processing_event_id=e.event_id AND d.processing_ingestion_seq=e.ingestion_seq
WHERE w.window_id=$1 AND w.state='ready' AND d.evidence_state='active' AND NOT EXISTS(SELECT 1 FROM cheesetrap.report_candidates c WHERE c.window_id=w.window_id AND c.source_ip=d.source_ip)
GROUP BY d.source_ip ORDER BY d.source_ip LIMIT 1;

-- Count actual unowned membership once per physical chunk, then reuse that
-- count across roots. Chunk buckets are disjoint within a root; header counts
-- and bucket ranges do not establish actual evidence membership.
-- name: ListReportSourceDetections :many
WITH roots AS MATERIALIZED (
 SELECT d.* FROM cheesetrap.report_windows w
 JOIN cheesetrap.events e ON e.ingested_at>=w.start_at AND e.ingested_at<w.end_at AND e.ingestion_seq<=w.sealed_seq
 JOIN cheesetrap.detection_results d ON d.processing_event_id=e.event_id AND d.processing_ingestion_seq=e.ingestion_seq
 WHERE w.window_id=$1 AND w.state='ready' AND d.evidence_state='active' AND d.source_ip=$2
), chunk_refs AS MATERIALIZED (
 SELECT r.detection_id,r.chunk_id FROM roots d
 JOIN cheesetrap.detection_evidence_chunks r USING(detection_id)
 WHERE d.evidence_representation='chunks-v1'
), chunks AS MATERIALIZED (
 SELECT DISTINCT chunk_id FROM chunk_refs
), chunk_counts AS MATERIALIZED (
 SELECT c.chunk_id,count(*)::bigint AS attached_count FROM chunks c
 JOIN cheesetrap.evidence_chunk_members m USING(chunk_id)
 WHERE NOT EXISTS(SELECT 1 FROM cheesetrap.report_evidence re WHERE re.event_id=m.event_id)
 GROUP BY c.chunk_id
), chunk_root_counts AS (
 SELECT r.detection_id,sum(c.attached_count)::bigint AS attached_count FROM chunk_refs r
 JOIN chunk_counts c USING(chunk_id) GROUP BY r.detection_id
), legacy_counts AS (
 SELECT d.detection_id,count(*)::bigint AS attached_count FROM roots d
 JOIN cheesetrap.detection_evidence de USING(detection_id)
 WHERE d.evidence_representation='legacy'
 AND NOT EXISTS(SELECT 1 FROM cheesetrap.report_evidence re WHERE re.event_id=de.event_id)
 GROUP BY d.detection_id
)
SELECT d.*,coalesce(c.attached_count,l.attached_count,0)::bigint AS attached_count FROM roots d
LEFT JOIN chunk_root_counts c USING(detection_id)
LEFT JOIN legacy_counts l USING(detection_id)
ORDER BY d.processing_ingestion_seq,d.rule_id,d.signature_id,d.detection_id;

-- Deduplicate chunks before expanding actual membership. The final UNION also
-- removes evidence shared by distinct chunks or by legacy and chunk roots.
-- name: ListReportCandidateEvidence :many
WITH roots AS MATERIALIZED (
 SELECT d.detection_id,d.evidence_representation FROM cheesetrap.report_windows w
 JOIN cheesetrap.events trigger ON trigger.ingested_at>=w.start_at AND trigger.ingested_at<w.end_at AND trigger.ingestion_seq<=w.sealed_seq
 JOIN cheesetrap.detection_results d ON d.processing_event_id=trigger.event_id AND d.processing_ingestion_seq=trigger.ingestion_seq
 WHERE w.window_id=$1 AND w.state='ready' AND d.evidence_state='active' AND d.source_ip=$2
), chunks AS MATERIALIZED (
 SELECT DISTINCT r.chunk_id FROM roots d
 JOIN cheesetrap.detection_evidence_chunks r USING(detection_id)
 WHERE d.evidence_representation='chunks-v1'
), evidence_ids AS (
 SELECT m.event_id FROM chunks c JOIN cheesetrap.evidence_chunk_members m USING(chunk_id)
 UNION
 SELECT de.event_id FROM roots d JOIN cheesetrap.detection_evidence de USING(detection_id)
 WHERE d.evidence_representation='legacy'
)
SELECT e.* FROM cheesetrap.processing_events e JOIN evidence_ids ids USING(event_id)
WHERE NOT EXISTS(SELECT 1 FROM cheesetrap.report_evidence re WHERE re.event_id=e.event_id)
ORDER BY e.ingestion_seq;

-- name: ReportEvidenceGap :one
SELECT jsonb_build_object('started_at',min(started_at),'observed_through',max(observed_through),
 'incidents',jsonb_agg(jsonb_build_object('started_at',started_at,'observed_through',observed_through,'causes',causes) ORDER BY started_at,incident_id))::jsonb AS gap
FROM cheesetrap.collection_gap_incidents WHERE sensor_id=sqlc.arg(sensor_id)::uuid
 AND started_at<sqlc.arg(window_end)::timestamptz AND observed_through>=sqlc.arg(window_start)::timestamptz HAVING count(*)>0;

-- name: CompleteReportWindow :exec
INSERT INTO cheesetrap.report_window_completions(window_id) VALUES($1);

-- name: RecordReportCandidate :exec
INSERT INTO cheesetrap.report_candidates(window_id,source_ip,outcome,report_id) VALUES($1,$2,$3,$4);

-- name: CreateReport :one
INSERT INTO cheesetrap.reports(window_id,source_ip) VALUES($1,$2) RETURNING *;

-- Keep the large snapshot parameter last to avoid pgx parameter/wire buffer
-- growth copying it again; VALUES still maps it to the snapshot column.
-- name: AppendReportRevision :one
INSERT INTO cheesetrap.report_revisions(report_id,version,snapshot,subject,body,recipient,reply_to,hold_reasons,state,auto_approval_allowed,body_edited,content_digest) VALUES($1,$2,$12,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING revision_id;

-- name: AdvanceReportRevision :execrows
UPDATE cheesetrap.reports SET current_revision_id=$2,version=version+1,state=$3,active_refresh_id=NULL WHERE report_id=$1 AND version=$4;

-- name: LockReport :one
SELECT * FROM cheesetrap.reports WHERE report_id=$1 FOR UPDATE;

-- name: CurrentReportRevision :one
SELECT v.* FROM cheesetrap.report_revisions v JOIN cheesetrap.reports r ON r.report_id=v.report_id AND r.current_revision_id=v.revision_id WHERE r.report_id=$1;

-- name: SetReportReplyTo :exec
INSERT INTO cheesetrap.settings(key,version,value) VALUES('reporting_reply_to',1,jsonb_build_object('address',sqlc.arg(address)::text)) ON CONFLICT(key) DO UPDATE SET version=settings.version+1,value=EXCLUDED.value,updated_at=clock_timestamp();

-- Freshness uses actual database time, not the sealed ingestion-window floor.
-- name: ReportRevisionClock :one
SELECT clock_timestamp()::timestamptz AS now;

-- name: CopyReportEvidenceBatch :exec
INSERT INTO cheesetrap.report_evidence(event_id,report_id,snapshot)
SELECT (entry->>'event_id')::uuid,sqlc.arg(report_id)::uuid,entry FROM jsonb_array_elements(sqlc.arg(snapshots)::jsonb) entry;
