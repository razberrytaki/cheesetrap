-- +goose Up
-- Resolve actual immutable membership only. Bucket ranges never imply evidence.
-- Retiring roots may be partial during future bounded cleanup and are invisible.
CREATE VIEW cheesetrap.detection_evidence_membership WITH (security_invoker=true) AS
 SELECT d.detection_id,e.event_id
 FROM cheesetrap.detection_results d
 JOIN cheesetrap.detection_evidence e USING(detection_id)
 WHERE d.evidence_representation='legacy' AND d.evidence_state='active'
 UNION ALL
 SELECT d.detection_id,m.event_id
 FROM cheesetrap.detection_results d
 JOIN cheesetrap.detection_evidence_chunks r USING(detection_id)
 JOIN cheesetrap.evidence_chunk_members m USING(chunk_id)
 WHERE d.evidence_representation='chunks-v1' AND d.evidence_state='active';
GRANT SELECT ON cheesetrap.detection_evidence_membership TO cheesetrap_api,cheesetrap_worker;

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN RAISE EXCEPTION 'evidence_membership_downgrade_requires_compatible_readers'; END $$;
-- +goose StatementEnd
