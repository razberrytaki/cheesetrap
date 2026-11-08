-- +goose Up
-- Validate append bounds once per reference INSERT, preserving the same
-- transaction-visible count/width invariants and every row-level state guard.
-- The writer batches only reference insertion; exact collision comparisons,
-- event membership checks, retry checks, and deferred proof validation remain.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION cheesetrap.guard_evidence_membership() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,cheesetrap AS $$
DECLARE c cheesetrap.evidence_chunks; r cheesetrap.detection_results; seq bigint;
BEGIN
 IF session_user='cheesetrap_worker' AND current_user=pg_get_userbyid((SELECT nspowner FROM pg_namespace WHERE nspname='cheesetrap')) THEN
  IF TG_OP='UPDATE' AND TG_TABLE_NAME='evidence_chunks' THEN
   IF NOT OLD.retired AND NEW.retired AND (to_jsonb(OLD)-'retired')=(to_jsonb(NEW)-'retired') AND NOT EXISTS(SELECT 1 FROM cheesetrap.detection_evidence_chunks WHERE chunk_id=OLD.chunk_id) THEN RETURN NEW; END IF;
  ELSIF TG_OP='DELETE' THEN
   IF TG_TABLE_NAME='detection_evidence_chunks' THEN
    IF EXISTS(SELECT 1 FROM cheesetrap.detection_results WHERE detection_id=OLD.detection_id AND evidence_state='retiring') THEN RETURN OLD; END IF;
   ELSIF TG_TABLE_NAME='evidence_chunk_members' THEN
    IF EXISTS(SELECT 1 FROM cheesetrap.evidence_chunks WHERE chunk_id=OLD.chunk_id AND retired) AND NOT EXISTS(SELECT 1 FROM cheesetrap.detection_evidence_chunks WHERE chunk_id=OLD.chunk_id) THEN RETURN OLD; END IF;
   ELSIF TG_TABLE_NAME='evidence_chunks' THEN
    IF OLD.retired AND NOT EXISTS(SELECT 1 FROM cheesetrap.evidence_chunk_members WHERE chunk_id=OLD.chunk_id) AND NOT EXISTS(SELECT 1 FROM cheesetrap.detection_evidence_chunks WHERE chunk_id=OLD.chunk_id) THEN RETURN OLD; END IF;
   END IF;
  END IF;
 END IF;
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'evidence_chunk_immutable' USING ERRCODE='23514'; END IF;
 IF TG_TABLE_NAME='evidence_chunks' THEN
  IF NEW.retired THEN RAISE EXCEPTION 'invalid_chunk_state' USING ERRCODE='23514'; END IF;
 ELSIF TG_TABLE_NAME='detection_evidence' THEN
  SELECT * INTO r FROM cheesetrap.detection_results WHERE detection_id=NEW.detection_id;
  IF r.evidence_representation<>'legacy' OR r.evidence_state<>'active' THEN RAISE EXCEPTION 'mixed_evidence' USING ERRCODE='23514'; END IF;
 ELSIF TG_TABLE_NAME='evidence_chunk_members' THEN
  SELECT * INTO c FROM cheesetrap.evidence_chunks WHERE chunk_id=NEW.chunk_id;
  SELECT ingestion_seq INTO seq FROM cheesetrap.events WHERE event_id=NEW.event_id;
  IF c.retired OR (seq-1)/c.bucket_width<>c.bucket_no OR (SELECT count(*) FROM cheesetrap.evidence_chunk_members WHERE chunk_id=NEW.chunk_id)>=c.member_count OR EXISTS(SELECT 1 FROM cheesetrap.detection_evidence_chunks WHERE chunk_id=NEW.chunk_id) THEN RAISE EXCEPTION 'invalid_chunk_member' USING ERRCODE='23514'; END IF;
 ELSE
  SELECT * INTO c FROM cheesetrap.evidence_chunks WHERE chunk_id=NEW.chunk_id;
  SELECT * INTO r FROM cheesetrap.detection_results WHERE detection_id=NEW.detection_id;
  IF c.retired OR c.bucket_no<>NEW.bucket_no OR r.evidence_representation<>'chunks-v1' OR r.evidence_state<>'active' THEN RAISE EXCEPTION 'invalid_chunk_reference' USING ERRCODE='23514'; END IF;
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE FUNCTION cheesetrap.guard_evidence_attachments() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,cheesetrap AS $$
BEGIN
 -- Check the final state of every root touched by this INSERT statement. This
 -- remains immediate (not deferred), including direct owner writes, and sees
 -- earlier statements as well as every row in the current transition table.
 IF EXISTS(
  SELECT 1 FROM (SELECT DISTINCT detection_id FROM inserted_evidence_refs) touched
  JOIN cheesetrap.detection_results r USING(detection_id)
  JOIN cheesetrap.detection_evidence_chunks d USING(detection_id)
  JOIN cheesetrap.evidence_chunks c USING(chunk_id)
  GROUP BY r.detection_id,r.evidence_count
  HAVING sum(c.member_count)>r.evidence_count OR count(DISTINCT c.bucket_width)>1
 ) THEN RAISE EXCEPTION 'invalid_chunk_attachment' USING ERRCODE='23514'; END IF;
 RETURN NULL;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION cheesetrap.store_detection_chunks(root_id uuid,width integer,event_ids uuid[]) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,cheesetrap AS $$
DECLARE r cheesetrap.detection_results; ids uuid[]; stored uuid[]; part record; cid uuid; digest text; chunk_ids uuid[]:=ARRAY[]::uuid[]; buckets bigint[]:=ARRAY[]::bigint[];
BEGIN
 -- Cursor first, including direct calls: shared with ingestion and cleanup.
 PERFORM 1 FROM cheesetrap.processing_cursors WHERE singleton FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'missing_processing_cursor' USING ERRCODE='23514'; END IF;
 SELECT * INTO r FROM cheesetrap.detection_results WHERE detection_id=root_id FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'missing_detection' USING ERRCODE='23503'; END IF;
 IF r.evidence_state<>'active' THEN RAISE EXCEPTION 'retired_result' USING ERRCODE='23514'; END IF;
 IF width IS NULL OR width NOT IN (64,128,256) OR event_ids IS NULL OR cardinality(event_ids)<>r.evidence_count OR array_position(event_ids,NULL) IS NOT NULL THEN RAISE EXCEPTION 'invalid_evidence_set' USING ERRCODE='23514'; END IF;
 SELECT array_agg(DISTINCT id ORDER BY id) INTO ids FROM unnest(event_ids) id;
 IF cardinality(ids)<>cardinality(event_ids) THEN RAISE EXCEPTION 'duplicate_evidence' USING ERRCODE='23514'; END IF;
 IF EXISTS(SELECT 1 FROM unnest(ids) id WHERE NOT EXISTS(SELECT 1 FROM cheesetrap.events e WHERE e.event_id=id)) THEN RAISE EXCEPTION 'missing_evidence_event' USING ERRCODE='23503'; END IF;
 IF r.evidence_hash<>cheesetrap.evidence_set_hash(ids) THEN RAISE EXCEPTION 'evidence_hash_mismatch' USING ERRCODE='23514'; END IF;
 IF r.evidence_representation='legacy' THEN
  SELECT array_agg(event_id ORDER BY event_id) INTO stored FROM cheesetrap.detection_evidence WHERE detection_id=root_id;
  IF stored IS DISTINCT FROM ids THEN RAISE EXCEPTION 'evidence_retry_mismatch' USING ERRCODE='23514'; END IF;
  RETURN;
 END IF;
 IF EXISTS(SELECT 1 FROM cheesetrap.detection_evidence_chunks WHERE detection_id=root_id) THEN
  SELECT array_agg(m.event_id ORDER BY m.event_id) INTO stored FROM cheesetrap.detection_evidence_chunks d JOIN cheesetrap.evidence_chunk_members m USING(chunk_id) WHERE d.detection_id=root_id;
  IF stored IS DISTINCT FROM ids THEN RAISE EXCEPTION 'evidence_retry_mismatch' USING ERRCODE='23514'; END IF;
  RETURN;
 END IF;
 FOR part IN SELECT (e.ingestion_seq-1)/width AS bucket,array_agg(e.event_id ORDER BY e.event_id) AS members FROM cheesetrap.events e WHERE e.event_id=ANY(ids) GROUP BY (e.ingestion_seq-1)/width ORDER BY 1 LOOP
  digest:=cheesetrap.chunk_content_hash(width,part.bucket,part.members);
  SELECT chunk_id INTO cid FROM cheesetrap.evidence_chunks WHERE encoding_version=1 AND bucket_width=width AND bucket_no=part.bucket AND content_hash=digest AND NOT retired;
  IF FOUND THEN
   SELECT array_agg(event_id ORDER BY event_id) INTO stored FROM cheesetrap.evidence_chunk_members WHERE chunk_id=cid;
   IF stored IS DISTINCT FROM part.members THEN RAISE EXCEPTION 'chunk_content_collision' USING ERRCODE='23514'; END IF;
  ELSE
   INSERT INTO cheesetrap.evidence_chunks(bucket_width,bucket_no,content_hash,member_count) VALUES(width,part.bucket,digest,cardinality(part.members)) RETURNING chunk_id INTO cid;
   INSERT INTO cheesetrap.evidence_chunk_members SELECT cid,unnest(part.members);
  END IF;
  chunk_ids:=array_append(chunk_ids,cid);
  buckets:=array_append(buckets,part.bucket);
 END LOOP;
 INSERT INTO cheesetrap.detection_evidence_chunks SELECT root_id,bucket,chunk_id FROM unnest(buckets,chunk_ids) AS refs(bucket,chunk_id);
END $$;
-- +goose StatementEnd
CREATE TRIGGER guard_chunk_attachments AFTER INSERT ON cheesetrap.detection_evidence_chunks REFERENCING NEW TABLE AS inserted_evidence_refs FOR EACH STATEMENT EXECUTE FUNCTION cheesetrap.guard_evidence_attachments();

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN RAISE EXCEPTION 'chunk_attachment_batch_downgrade_requires_data_preservation'; END $$;
-- +goose StatementEnd
