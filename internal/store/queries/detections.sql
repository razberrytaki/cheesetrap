-- Caller first locks processing_cursors; no external I/O inside this transaction.
-- No context LIMIT: dropping evidence could suppress a valid window.
-- name: ListDetectionBatch :many
SELECT * FROM cheesetrap.events WHERE ingestion_seq>sqlc.arg(after_seq)::bigint AND ingestion_seq<=sqlc.arg(through_seq)::bigint ORDER BY ingestion_seq LIMIT sqlc.arg(batch_limit)::integer;

-- name: ListDetectionContext :many
SELECT e.* FROM cheesetrap.events e
JOIN cheesetrap.detection_completions c ON c.event_id=e.event_id AND c.ingestion_seq=e.ingestion_seq
WHERE e.source_ip=sqlc.arg(source_ip)::inet AND e.event_type=sqlc.arg(event_type)::text AND e.ingestion_seq<sqlc.arg(processing_seq)::bigint
 AND e.observed_at>=sqlc.arg(window_start)::timestamptz AND e.observed_at<=sqlc.arg(window_end)::timestamptz
ORDER BY e.observed_at,e.ingestion_seq;

-- name: DetectionSensorHasGap :one
SELECT EXISTS(SELECT 1 FROM cheesetrap.ingestion_gaps WHERE sensor_id=$1) AS has_gap;

-- name: InsertDetectionResult :one
INSERT INTO cheesetrap.detection_results(rule_id,rule_version,signature_id,signature_version,processing_event_id,processing_ingestion_seq,source_ip,window_start,window_end,evidence_hash,evidence_count,evidence_eligible,auto_approval_allowed,explanation,settings_version)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
ON CONFLICT(rule_id,rule_version,signature_id,signature_version,processing_event_id,evidence_hash) DO NOTHING RETURNING detection_id;

-- name: GetDetectionIdentity :one
SELECT detection_id FROM cheesetrap.detection_results WHERE rule_id=$1 AND rule_version=$2 AND signature_id=$3 AND signature_version=$4 AND processing_event_id=$5 AND evidence_hash=$6;

-- name: InsertDetectionEvidence :exec
INSERT INTO cheesetrap.detection_evidence(detection_id,event_id)
SELECT sqlc.arg(detection_id)::uuid, unnest(sqlc.arg(event_ids)::uuid[])
ON CONFLICT DO NOTHING;

-- name: CompleteDetectionEvent :exec
INSERT INTO cheesetrap.detection_completions(ingestion_seq,event_id,rule_set_version,settings_version) VALUES($1,$2,$3,$4) ON CONFLICT(ingestion_seq) DO NOTHING;

-- name: AdvanceContinuousDetectedCursor :execrows
UPDATE cheesetrap.processing_cursors SET detected_seq=sqlc.arg(next_seq)::bigint WHERE singleton AND detected_seq=sqlc.arg(previous_seq)::bigint AND ingested_seq>=sqlc.arg(next_seq)::bigint;

-- Storage-only entry points; production processor switches in Task 2.
-- name: InsertChunkDetectionResult :one
INSERT INTO cheesetrap.detection_results(rule_id,rule_version,signature_id,signature_version,processing_event_id,processing_ingestion_seq,source_ip,window_start,window_end,evidence_hash,evidence_count,evidence_eligible,auto_approval_allowed,explanation,settings_version,evidence_representation)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,'chunks-v1')
ON CONFLICT(rule_id,rule_version,signature_id,signature_version,processing_event_id,evidence_hash) DO NOTHING RETURNING detection_id;

-- name: GetStoredDetectionIdentity :one
SELECT detection_id,evidence_representation,evidence_state FROM cheesetrap.detection_results WHERE rule_id=$1 AND rule_version=$2 AND signature_id=$3 AND signature_version=$4 AND processing_event_id=$5 AND evidence_hash=$6;

-- name: StoreDetectionChunks :exec
SELECT cheesetrap.store_detection_chunks(sqlc.arg(detection_id)::uuid,sqlc.arg(bucket_width)::integer,sqlc.arg(event_ids)::uuid[]);
