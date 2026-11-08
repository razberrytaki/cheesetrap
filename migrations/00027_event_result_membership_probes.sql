-- +goose Up
-- EXISTS favors low startup cost and may otherwise start with all detection
-- roots/references for every event. Keep the exact event membership boundary
-- materialized, then preserve parameterized probes with OFFSET 0 barriers.
-- This changes only lookup work, not proof/state/snapshot classification.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION cheesetrap.event_detection_result(id uuid,seq bigint,processed bigint)
RETURNS text LANGUAGE sql STABLE SET search_path=pg_catalog,cheesetrap AS $$
 SELECT CASE WHEN seq>processed THEN 'pending'
 WHEN EXISTS(SELECT 1 FROM cheesetrap.event_evidence_history h WHERE h.event_id=id AND h.first_detection_seq<=processed)
 OR EXISTS(
  WITH matched AS MATERIALIZED (SELECT m.detection_id FROM cheesetrap.detection_evidence m WHERE m.event_id=id)
  SELECT 1 FROM matched m
  CROSS JOIN LATERAL (
   SELECT 1 FROM cheesetrap.detection_results d WHERE d.detection_id=m.detection_id
    AND d.evidence_representation='legacy' AND d.evidence_state='active' AND d.processing_ingestion_seq<=processed
   OFFSET 0
  ) proof
 )
 OR EXISTS(
  WITH matched AS MATERIALIZED (SELECT m.chunk_id FROM cheesetrap.evidence_chunk_members m WHERE m.event_id=id)
  SELECT 1 FROM matched m
  CROSS JOIN LATERAL (
   SELECT r.detection_id FROM cheesetrap.detection_evidence_chunks r WHERE r.chunk_id=m.chunk_id OFFSET 0
  ) r
  CROSS JOIN LATERAL (
   SELECT 1 FROM cheesetrap.detection_results d WHERE d.detection_id=r.detection_id
    AND d.evidence_representation='chunks-v1' AND d.evidence_state='active' AND d.processing_ingestion_seq<=processed
   OFFSET 0
  ) proof
 )
 THEN 'evidence' ELSE 'no_match' END
$$;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN RAISE EXCEPTION 'event_result_query_downgrade_not_supported'; END $$;
-- +goose StatementEnd
