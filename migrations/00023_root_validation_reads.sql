-- +goose Up
-- Preserve the full deferred proof while avoiding unrelated header/member scans.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION cheesetrap.validate_evidence_root() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,cheesetrap AS $$
DECLARE r cheesetrap.detection_results; n bigint; unique_n bigint; widths bigint; ids uuid[];
BEGIN
 SELECT * INTO r FROM cheesetrap.detection_results WHERE detection_id=NEW.detection_id;
 IF NOT FOUND OR r.evidence_state='retiring' THEN RETURN NULL; END IF;
 IF r.evidence_representation='chunks-v1' THEN
  -- Keep both physical reads parameterized by this root's references even before ANALYZE.
  -- OFFSET 0 prevents join flattening without limiting any actual proof members.
  SELECT count(*),count(DISTINCT m.event_id),count(DISTINCT c.bucket_width),array_agg(m.event_id ORDER BY m.event_id) INTO n,unique_n,widths,ids FROM cheesetrap.detection_evidence_chunks d
  CROSS JOIN LATERAL (SELECT bucket_width FROM cheesetrap.evidence_chunks WHERE chunk_id=d.chunk_id OFFSET 0) c
  CROSS JOIN LATERAL (SELECT event_id FROM cheesetrap.evidence_chunk_members WHERE chunk_id=d.chunk_id OFFSET 0) m
  WHERE d.detection_id=r.detection_id;
  IF n<>r.evidence_count OR n<>unique_n OR widths<>1 OR r.evidence_hash IS DISTINCT FROM cheesetrap.evidence_set_hash(ids) OR EXISTS(SELECT 1 FROM cheesetrap.detection_evidence WHERE detection_id=r.detection_id) THEN RAISE EXCEPTION 'incomplete_evidence_root' USING ERRCODE='23514'; END IF;
 END IF;
 RETURN NULL;
END $$;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN RAISE EXCEPTION 'root_validation_reads_downgrade_requires_review'; END $$;
-- +goose StatementEnd
