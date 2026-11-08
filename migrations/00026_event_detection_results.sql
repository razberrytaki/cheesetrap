-- +goose Up
-- Freeze the backfill/copy boundary in the established runtime lock order.
-- Otherwise a copy committed between backfill and trigger installation could
-- later lose its classification when its root retires.
-- +goose StatementBegin
DO $$ BEGIN
 PERFORM 1 FROM cheesetrap.processing_cursors WHERE singleton FOR UPDATE;
 PERFORM 1 FROM cheesetrap.report_draft_lock WHERE singleton FOR UPDATE;
END $$;
-- +goose StatementEnd
LOCK TABLE cheesetrap.report_evidence IN SHARE ROW EXCLUSIVE MODE;
-- A compact provenance marker is written once per copied event, never once per
-- detection. Its lifetime is the retained event's lifetime; report/root cleanup
-- cannot turn known evidence into no_match. Existing copied evidence predates
-- all v2 cursors, so 0 is a valid bound when its original root is already gone.
CREATE TABLE cheesetrap.event_evidence_history (
 event_id uuid PRIMARY KEY REFERENCES cheesetrap.events ON DELETE CASCADE,
 first_detection_seq bigint NOT NULL CHECK(first_detection_seq>=0)
);
INSERT INTO cheesetrap.event_evidence_history(event_id,first_detection_seq)
WITH copied AS MATERIALIZED (SELECT re.event_id FROM cheesetrap.report_evidence re JOIN cheesetrap.events e USING(event_id)),
 selected_chunks AS MATERIALIZED (SELECT DISTINCT m.chunk_id FROM copied n JOIN cheesetrap.evidence_chunk_members m USING(event_id)),
 chunk_first AS MATERIALIZED (
  SELECT c.chunk_id,min(d.processing_ingestion_seq) AS seq FROM selected_chunks c
  JOIN cheesetrap.detection_evidence_chunks r USING(chunk_id) JOIN cheesetrap.detection_results d USING(detection_id)
  WHERE d.evidence_representation='chunks-v1' GROUP BY c.chunk_id
 ), proof AS (
  SELECT n.event_id,d.processing_ingestion_seq AS seq FROM copied n
  JOIN cheesetrap.detection_evidence m USING(event_id) JOIN cheesetrap.detection_results d USING(detection_id)
  WHERE d.evidence_representation='legacy'
  UNION ALL
  SELECT n.event_id,c.seq FROM copied n JOIN cheesetrap.evidence_chunk_members m USING(event_id)
  JOIN chunk_first c USING(chunk_id)
 )
SELECT n.event_id,coalesce(min(p.seq),0) FROM copied n LEFT JOIN proof p USING(event_id) GROUP BY n.event_id;
GRANT SELECT ON cheesetrap.event_evidence_history TO cheesetrap_api,cheesetrap_worker;

-- Batch transition-table processing preserves the report writer's batching.
-- Join actual indexed membership, not bucket ranges or observed timestamps.
-- +goose StatementBegin
CREATE FUNCTION cheesetrap.remember_copied_event_evidence() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,cheesetrap SET jit=off AS $$
BEGIN
 INSERT INTO cheesetrap.event_evidence_history(event_id,first_detection_seq)
 WITH selected_chunks AS MATERIALIZED (
  SELECT DISTINCT m.chunk_id FROM copied_events n JOIN cheesetrap.evidence_chunk_members m USING(event_id)
 ), chunk_first AS MATERIALIZED (
  SELECT c.chunk_id,min(d.processing_ingestion_seq) AS seq FROM selected_chunks c
  JOIN cheesetrap.detection_evidence_chunks r USING(chunk_id) JOIN cheesetrap.detection_results d USING(detection_id)
  WHERE d.evidence_representation='chunks-v1' AND d.evidence_state='active' GROUP BY c.chunk_id
 ), proof AS (
  SELECT n.event_id,d.processing_ingestion_seq AS seq
  FROM copied_events n JOIN cheesetrap.detection_evidence m USING(event_id)
  JOIN cheesetrap.detection_results d USING(detection_id)
  WHERE d.evidence_representation='legacy' AND d.evidence_state='active'
  UNION ALL
  SELECT n.event_id,c.seq FROM copied_events n JOIN cheesetrap.evidence_chunk_members m USING(event_id)
  JOIN chunk_first c USING(chunk_id)
 )
 SELECT event_id,min(seq) FROM proof GROUP BY event_id
 ON CONFLICT(event_id) DO UPDATE SET first_detection_seq=least(event_evidence_history.first_detection_seq,EXCLUDED.first_detection_seq);
 RETURN NULL;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION cheesetrap.remember_copied_event_evidence() FROM PUBLIC;
CREATE TRIGGER remember_copied_event_evidence AFTER INSERT ON cheesetrap.report_evidence
 REFERENCING NEW TABLE AS copied_events FOR EACH STATEMENT EXECUTE FUNCTION cheesetrap.remember_copied_event_evidence();

CREATE TABLE cheesetrap.event_list_state (
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
 epoch bigint NOT NULL DEFAULT 0 CHECK(epoch>=0)
);
INSERT INTO cheesetrap.event_list_state DEFAULT VALUES;
GRANT SELECT ON cheesetrap.event_list_state TO cheesetrap_api;
-- Deletion invalidates list snapshots; classification proof itself survives
-- root and report deletion. Empty cleanup statements do not invalidate cursors.
-- +goose StatementBegin
CREATE FUNCTION cheesetrap.invalidate_event_list_snapshot() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,cheesetrap AS $$
BEGIN
 IF EXISTS(SELECT 1 FROM removed_events) THEN
  UPDATE cheesetrap.event_list_state SET epoch=epoch+1 WHERE singleton;
 END IF;
 RETURN NULL;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION cheesetrap.invalidate_event_list_snapshot() FROM PUBLIC;
CREATE TRIGGER invalidate_event_list_snapshot AFTER DELETE ON cheesetrap.events
 REFERENCING OLD TABLE AS removed_events FOR EACH STATEMENT EXECUTE FUNCTION cheesetrap.invalidate_event_list_snapshot();

-- +goose StatementBegin
CREATE FUNCTION cheesetrap.event_detection_result(id uuid,seq bigint,processed bigint)
RETURNS text LANGUAGE sql STABLE SET search_path=pg_catalog,cheesetrap AS $$
 SELECT CASE WHEN seq>processed THEN 'pending'
 WHEN EXISTS(SELECT 1 FROM cheesetrap.event_evidence_history h WHERE h.event_id=id AND h.first_detection_seq<=processed)
 OR EXISTS(SELECT 1 FROM cheesetrap.detection_evidence m JOIN cheesetrap.detection_results d USING(detection_id)
  WHERE m.event_id=id AND d.evidence_representation='legacy' AND d.evidence_state='active' AND d.processing_ingestion_seq<=processed)
 OR EXISTS(SELECT 1 FROM cheesetrap.evidence_chunk_members m JOIN cheesetrap.detection_evidence_chunks r USING(chunk_id)
  JOIN cheesetrap.detection_results d USING(detection_id)
  WHERE m.event_id=id AND d.evidence_representation='chunks-v1' AND d.evidence_state='active' AND d.processing_ingestion_seq<=processed)
 THEN 'evidence' ELSE 'no_match' END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION cheesetrap.event_detection_result(uuid,bigint,bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION cheesetrap.event_detection_result(uuid,bigint,bigint) TO cheesetrap_api;

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN RAISE EXCEPTION 'event_result_history_downgrade_requires_data_preservation'; END $$;
-- +goose StatementEnd
