-- +goose Up
ALTER TABLE cheesetrap.detection_results
 ADD COLUMN evidence_representation text NOT NULL DEFAULT 'legacy' CHECK(evidence_representation IN ('legacy','chunks-v1')),
 ADD COLUMN evidence_state text NOT NULL DEFAULT 'active' CHECK(evidence_state IN ('active','retiring'));
CREATE TABLE cheesetrap.evidence_chunks (
 chunk_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 encoding_version integer NOT NULL DEFAULT 1 CHECK(encoding_version=1),
 bucket_width integer NOT NULL CHECK(bucket_width IN (64,128,256)),
 bucket_no bigint NOT NULL CHECK(bucket_no>=0),
 content_hash text NOT NULL CHECK(content_hash ~ '^[a-f0-9]{64}$'),
 member_count integer NOT NULL CHECK(member_count>0 AND member_count<=bucket_width),
 retired boolean NOT NULL DEFAULT false
);
CREATE UNIQUE INDEX evidence_chunks_active_identity ON cheesetrap.evidence_chunks(encoding_version,bucket_width,bucket_no,content_hash) WHERE NOT retired;
CREATE TABLE cheesetrap.evidence_chunk_members (
 chunk_id uuid NOT NULL REFERENCES cheesetrap.evidence_chunks,
 event_id uuid NOT NULL REFERENCES cheesetrap.events,
 PRIMARY KEY(chunk_id,event_id)
);
CREATE INDEX evidence_chunk_members_event_idx ON cheesetrap.evidence_chunk_members(event_id);
CREATE TABLE cheesetrap.detection_evidence_chunks (
 detection_id uuid NOT NULL REFERENCES cheesetrap.detection_results,
 bucket_no bigint NOT NULL CHECK(bucket_no>=0),
 chunk_id uuid NOT NULL REFERENCES cheesetrap.evidence_chunks,
 PRIMARY KEY(detection_id,bucket_no)
);
CREATE INDEX detection_evidence_chunks_chunk_idx ON cheesetrap.detection_evidence_chunks(chunk_id);

-- SHA-256 of UTF-8: "chunks-v1:<decimal width>:<decimal bucket>:" followed
-- by comma-separated, lowercase hyphenated UUIDs in PostgreSQL UUID byte order.
-- The writer derives this identity; callers cannot supply a digest.
-- +goose StatementBegin
CREATE FUNCTION cheesetrap.chunk_content_hash(w integer,b bigint,ids uuid[]) RETURNS text
LANGUAGE sql IMMUTABLE STRICT SET search_path=pg_catalog,cheesetrap AS $$
 SELECT encode(sha256(convert_to('chunks-v1:'||w::text||':'||b::text||':'||array_to_string(ids,','),'UTF8')),'hex')
$$;
-- +goose StatementEnd

-- Existing Evaluate hashes Go JSON's compact array of sorted UUID strings.
-- array_to_json(uuid[]) uses that same canonical representation.
-- +goose StatementBegin
CREATE FUNCTION cheesetrap.evidence_set_hash(ids uuid[]) RETURNS text
LANGUAGE sql IMMUTABLE STRICT SET search_path=pg_catalog,cheesetrap AS $$
 SELECT encode(sha256(convert_to(array_to_json(ids)::text,'UTF8')),'hex')
$$;
-- +goose StatementEnd

-- Runtime result INSERT remains compatible with the legacy writer, but cannot
-- forge cleanup state. No GUC or session-controlled flag grants an exemption.
-- +goose StatementBegin
CREATE FUNCTION cheesetrap.guard_evidence_root() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,cheesetrap AS $$
BEGIN
 IF TG_OP='INSERT' AND NEW.evidence_state<>'active' THEN RAISE EXCEPTION 'invalid_evidence_state' USING ERRCODE='23514'; END IF;
 IF TG_OP='UPDATE' THEN RAISE EXCEPTION 'evidence_root_immutable' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER guard_evidence_root BEFORE INSERT OR UPDATE ON cheesetrap.detection_results FOR EACH ROW EXECUTE FUNCTION cheesetrap.guard_evidence_root();

-- +goose StatementBegin
CREATE FUNCTION cheesetrap.guard_evidence_membership() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,cheesetrap AS $$
DECLARE c cheesetrap.evidence_chunks; r cheesetrap.detection_results; seq bigint; attached bigint;
BEGIN
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
  SELECT coalesce(sum(h.member_count),0) INTO attached FROM cheesetrap.detection_evidence_chunks d JOIN cheesetrap.evidence_chunks h USING(chunk_id) WHERE d.detection_id=NEW.detection_id;
  IF attached+c.member_count>r.evidence_count OR EXISTS(SELECT 1 FROM cheesetrap.detection_evidence_chunks d JOIN cheesetrap.evidence_chunks h USING(chunk_id) WHERE d.detection_id=NEW.detection_id AND h.bucket_width<>c.bucket_width) THEN RAISE EXCEPTION 'invalid_chunk_attachment' USING ERRCODE='23514'; END IF;
  IF c.retired OR c.bucket_no<>NEW.bucket_no OR r.evidence_representation<>'chunks-v1' OR r.evidence_state<>'active' THEN RAISE EXCEPTION 'invalid_chunk_reference' USING ERRCODE='23514'; END IF;
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER guard_chunk_header BEFORE INSERT OR UPDATE OR DELETE ON cheesetrap.evidence_chunks FOR EACH ROW EXECUTE FUNCTION cheesetrap.guard_evidence_membership();
CREATE TRIGGER guard_legacy_evidence BEFORE INSERT ON cheesetrap.detection_evidence FOR EACH ROW EXECUTE FUNCTION cheesetrap.guard_evidence_membership();
CREATE TRIGGER guard_chunk_members BEFORE INSERT OR UPDATE OR DELETE ON cheesetrap.evidence_chunk_members FOR EACH ROW EXECUTE FUNCTION cheesetrap.guard_evidence_membership();
CREATE TRIGGER guard_chunk_refs BEFORE INSERT OR UPDATE OR DELETE ON cheesetrap.detection_evidence_chunks FOR EACH ROW EXECUTE FUNCTION cheesetrap.guard_evidence_membership();

-- Every new header and active root must be complete at transaction end. These
-- checks also cover migration-owner inserts; no writable finalized flag exists.
-- Immediate append bounds prevent extending complete headers/roots later,
-- without repeating full-set deferred scans for every member/reference.
-- +goose StatementBegin
CREATE FUNCTION cheesetrap.validate_evidence_chunk() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,cheesetrap AS $$
DECLARE c cheesetrap.evidence_chunks; ids uuid[];
BEGIN
 SELECT * INTO c FROM cheesetrap.evidence_chunks WHERE chunk_id=NEW.chunk_id;
 SELECT array_agg(event_id ORDER BY event_id) INTO ids FROM cheesetrap.evidence_chunk_members WHERE chunk_id=c.chunk_id;
 IF c.member_count<>coalesce(cardinality(ids),0) OR c.content_hash<>cheesetrap.chunk_content_hash(c.bucket_width,c.bucket_no,ids) THEN RAISE EXCEPTION 'incomplete_evidence_chunk' USING ERRCODE='23514'; END IF;
 RETURN NULL;
END $$;
-- +goose StatementEnd
CREATE CONSTRAINT TRIGGER complete_evidence_chunk AFTER INSERT ON cheesetrap.evidence_chunks DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION cheesetrap.validate_evidence_chunk();
-- +goose StatementBegin
CREATE FUNCTION cheesetrap.validate_evidence_root() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,cheesetrap AS $$
DECLARE r cheesetrap.detection_results; n bigint; unique_n bigint; widths bigint; ids uuid[];
BEGIN
 SELECT * INTO r FROM cheesetrap.detection_results WHERE detection_id=NEW.detection_id;
 IF r.evidence_representation='chunks-v1' THEN
  SELECT count(*),count(DISTINCT m.event_id),count(DISTINCT c.bucket_width),array_agg(m.event_id ORDER BY m.event_id) INTO n,unique_n,widths,ids FROM cheesetrap.detection_evidence_chunks d JOIN cheesetrap.evidence_chunks c USING(chunk_id) JOIN cheesetrap.evidence_chunk_members m USING(chunk_id) WHERE d.detection_id=r.detection_id;
  IF n<>r.evidence_count OR n<>unique_n OR widths<>1 OR r.evidence_hash IS DISTINCT FROM cheesetrap.evidence_set_hash(ids) OR EXISTS(SELECT 1 FROM cheesetrap.detection_evidence WHERE detection_id=r.detection_id) THEN RAISE EXCEPTION 'incomplete_evidence_root' USING ERRCODE='23514'; END IF;
 END IF;
 RETURN NULL;
END $$;
-- +goose StatementEnd
CREATE CONSTRAINT TRIGGER complete_evidence_root AFTER INSERT ON cheesetrap.detection_results DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION cheesetrap.validate_evidence_root();

-- +goose StatementBegin
CREATE FUNCTION cheesetrap.store_detection_chunks(root_id uuid,width integer,event_ids uuid[]) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,cheesetrap AS $$
DECLARE r cheesetrap.detection_results; ids uuid[]; stored uuid[]; part record; cid uuid; digest text;
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
  INSERT INTO cheesetrap.detection_evidence_chunks VALUES(root_id,part.bucket,cid);
 END LOOP;
END $$;
-- +goose StatementEnd
GRANT SELECT ON cheesetrap.evidence_chunks,cheesetrap.evidence_chunk_members,cheesetrap.detection_evidence_chunks TO cheesetrap_api,cheesetrap_worker;
REVOKE ALL ON FUNCTION cheesetrap.store_detection_chunks(uuid,integer,uuid[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION cheesetrap.store_detection_chunks(uuid,integer,uuid[]) TO cheesetrap_worker;

-- Task 1 is storage-only. Legacy cleanup cannot interpret chunks, so fail
-- closed until Task 3 replaces it with chunk-aware bounded retention.
-- Preserve the v14 implementation verbatim except its name and qualified OUT
-- parameter. A bare RENAME breaks PL/pgSQL's implicit function-block label.
-- +goose StatementBegin
CREATE FUNCTION cheesetrap.retention_cleanup_legacy(requested_now timestamptz,batch_limit integer)
RETURNS TABLE(deleted bigint,protected_events bigint) LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,cheesetrap SET statement_timeout='5s' SET lock_timeout='1s' AS $$
DECLARE at_time timestamptz:=least(requested_now,clock_timestamp()); n bigint; rid uuid; rev uuid; ids uuid[]; d_ids uuid[];
BEGIN
 IF requested_now IS NULL OR batch_limit IS NULL OR batch_limit<1 OR batch_limit>1000 THEN RAISE EXCEPTION 'invalid_cleanup'; END IF;
 deleted:=0;
 -- Serialize with ingestion/detection and drafting so eligibility and copies
 -- cannot change between selecting dependencies and deleting them.
 PERFORM 1 FROM cheesetrap.processing_cursors WHERE singleton FOR UPDATE;
 PERFORM 1 FROM cheesetrap.report_draft_lock WHERE singleton FOR UPDATE;
 -- A detection is expendable only after its window completed AND every
 -- referenced event was copied into immutable report evidence.
 SELECT array_agg(detection_id) INTO d_ids FROM (
 SELECT d.detection_id FROM cheesetrap.detection_results d JOIN cheesetrap.events e ON e.event_id=d.processing_event_id
 WHERE e.ingested_at<at_time-interval '30 days'
 AND EXISTS(SELECT 1 FROM cheesetrap.report_windows w JOIN cheesetrap.report_window_completions c USING(window_id) WHERE e.ingested_at>=w.start_at AND e.ingested_at<w.end_at)
 AND NOT EXISTS(SELECT 1 FROM cheesetrap.detection_evidence de WHERE de.detection_id=d.detection_id AND NOT EXISTS(SELECT 1 FROM cheesetrap.report_evidence re WHERE re.event_id=de.event_id))
 ORDER BY d.processing_ingestion_seq LIMIT batch_limit) x;
 -- Delete evidence links in bounded chunks before removing detection roots.
 DELETE FROM cheesetrap.detection_evidence WHERE (detection_id,event_id) IN (SELECT detection_id,event_id FROM cheesetrap.detection_evidence WHERE detection_id=ANY(d_ids) LIMIT batch_limit);
 GET DIAGNOSTICS n=ROW_COUNT;deleted:=deleted+n;
 DELETE FROM cheesetrap.detection_results d WHERE detection_id=ANY(d_ids) AND NOT EXISTS(SELECT 1 FROM cheesetrap.detection_evidence e WHERE e.detection_id=d.detection_id);
 GET DIAGNOSTICS n=ROW_COUNT;deleted:=deleted+n;
 SELECT array_agg(event_id) INTO ids FROM (
 SELECT e.event_id FROM cheesetrap.events e,cheesetrap.processing_cursors c WHERE c.singleton
 AND e.ingested_at<at_time-interval '30 days' AND e.ingestion_seq<=c.detected_seq AND e.ingested_at<c.sealed_before
 AND NOT EXISTS(SELECT 1 FROM cheesetrap.detection_evidence d WHERE d.event_id=e.event_id)
 AND NOT EXISTS(SELECT 1 FROM cheesetrap.detection_results d WHERE d.processing_event_id=e.event_id)
 ORDER BY e.ingestion_seq LIMIT batch_limit) x;
 DELETE FROM cheesetrap.detection_completions WHERE event_id=ANY(ids);
 GET DIAGNOSTICS n=ROW_COUNT;deleted:=deleted+n;
 DELETE FROM cheesetrap.events WHERE event_id=ANY(ids);
 GET DIAGNOSTICS n=ROW_COUNT;deleted:=deleted+n;
 -- One terminal report per pass; every child statement is bounded. The report
 -- and current revision remain until all other dependencies have been pruned.
 SELECT report_id,current_revision_id INTO rid,rev FROM cheesetrap.reports r
 WHERE last_changed_at<at_time-interval '180 days' AND (state='closed_unconfirmed' OR (state IN ('sent','rejected') AND NOT delivery_uncertain))
 AND active_refresh_id IS NULL
 ORDER BY last_changed_at LIMIT 1 FOR UPDATE;
 IF rid IS NOT NULL THEN
 DELETE FROM cheesetrap.delivery_attempts WHERE attempt_id IN (SELECT attempt_id FROM cheesetrap.delivery_attempts WHERE report_id=rid LIMIT batch_limit);
 GET DIAGNOSTICS n=ROW_COUNT;deleted:=deleted+n;
 DELETE FROM cheesetrap.delivery_schedule WHERE approval_id IN (SELECT a.approval_id FROM cheesetrap.approvals a WHERE a.report_id=rid AND NOT EXISTS(SELECT 1 FROM cheesetrap.delivery_attempts d WHERE d.approval_id=a.approval_id) LIMIT batch_limit);
 GET DIAGNOSTICS n=ROW_COUNT;deleted:=deleted+n;
 DELETE FROM cheesetrap.approvals a WHERE approval_id IN (SELECT approval_id FROM cheesetrap.approvals x WHERE x.report_id=rid AND NOT EXISTS(SELECT 1 FROM cheesetrap.delivery_attempts d WHERE d.approval_id=x.approval_id) AND NOT EXISTS(SELECT 1 FROM cheesetrap.delivery_schedule d WHERE d.approval_id=x.approval_id) LIMIT batch_limit);
 GET DIAGNOSTICS n=ROW_COUNT;deleted:=deleted+n;
 DELETE FROM cheesetrap.contact_refresh_requests WHERE request_id IN (SELECT request_id FROM cheesetrap.contact_refresh_requests WHERE report_id=rid LIMIT batch_limit);
 GET DIAGNOSTICS n=ROW_COUNT;deleted:=deleted+n;
 DELETE FROM cheesetrap.delivery_closures WHERE report_id=rid;
 GET DIAGNOSTICS n=ROW_COUNT;deleted:=deleted+n;
 DELETE FROM cheesetrap.report_candidates WHERE (window_id,source_ip) IN (SELECT window_id,source_ip FROM cheesetrap.report_candidates WHERE report_id=rid LIMIT batch_limit);
 GET DIAGNOSTICS n=ROW_COUNT;deleted:=deleted+n;
 -- Do not remove copied evidence while detection references still need it.
 DELETE FROM cheesetrap.report_evidence WHERE report_id=rid AND event_id IN (SELECT re.event_id FROM cheesetrap.report_evidence re WHERE report_id=rid AND NOT EXISTS(SELECT 1 FROM cheesetrap.detection_evidence de WHERE de.event_id=re.event_id) LIMIT batch_limit);
 GET DIAGNOSTICS n=ROW_COUNT;deleted:=deleted+n;
 DELETE FROM cheesetrap.report_revisions WHERE revision_id IN (SELECT rr.revision_id FROM cheesetrap.report_revisions rr WHERE report_id=rid AND revision_id<>rev AND NOT EXISTS(SELECT 1 FROM cheesetrap.approvals a WHERE a.revision_id=rr.revision_id) AND NOT EXISTS(SELECT 1 FROM cheesetrap.delivery_attempts a WHERE a.revision_id=rr.revision_id) AND NOT EXISTS(SELECT 1 FROM cheesetrap.contact_refresh_requests f WHERE f.revision_id=rr.revision_id OR f.result_revision_id=rr.revision_id) LIMIT batch_limit);
 GET DIAGNOSTICS n=ROW_COUNT;deleted:=deleted+n;
 IF NOT EXISTS(SELECT 1 FROM cheesetrap.approvals WHERE report_id=rid) AND NOT EXISTS(SELECT 1 FROM cheesetrap.delivery_attempts WHERE report_id=rid) AND NOT EXISTS(SELECT 1 FROM cheesetrap.report_evidence WHERE report_id=rid) AND NOT EXISTS(SELECT 1 FROM cheesetrap.report_candidates WHERE report_id=rid) AND NOT EXISTS(SELECT 1 FROM cheesetrap.contact_refresh_requests WHERE report_id=rid) AND NOT EXISTS(SELECT 1 FROM cheesetrap.report_revisions WHERE report_id=rid AND revision_id<>rev) THEN
 DELETE FROM cheesetrap.report_revisions WHERE revision_id=rev;
 DELETE FROM cheesetrap.reports WHERE report_id=rid;deleted:=deleted+2;
 END IF;
 END IF;
 -- Standalone audit entries expire only when not tied to a surviving report.
 DELETE FROM cheesetrap.audit WHERE audit_id IN (SELECT a.audit_id FROM cheesetrap.audit a WHERE created_at<at_time-interval '180 days' AND NOT EXISTS(SELECT 1 FROM cheesetrap.reports r WHERE a.details->>'report_id'=r.report_id::text) ORDER BY created_at LIMIT batch_limit);
 GET DIAGNOSTICS n=ROW_COUNT;deleted:=deleted+n;
 DELETE FROM cheesetrap_river.river_job WHERE id IN (SELECT id FROM cheesetrap_river.river_job WHERE state='completed' AND finalized_at<at_time-interval '7 days' ORDER BY finalized_at LIMIT batch_limit);
 GET DIAGNOSTICS n=ROW_COUNT;deleted:=deleted+n;
 SELECT count(*) INTO protected_events FROM cheesetrap.events e,cheesetrap.processing_cursors c WHERE c.singleton AND e.ingested_at<at_time-interval '30 days' AND (e.ingestion_seq>c.detected_seq OR e.ingested_at>=c.sealed_before OR EXISTS(SELECT 1 FROM cheesetrap.detection_evidence de WHERE de.event_id=e.event_id) OR EXISTS(SELECT 1 FROM cheesetrap.detection_results d WHERE d.processing_event_id=e.event_id));
 UPDATE cheesetrap.retention_status SET protected_events=retention_cleanup_legacy.protected_events,checked_at=at_time WHERE singleton;
 RETURN NEXT;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION cheesetrap.retention_cleanup_legacy(timestamptz,integer) FROM PUBLIC;
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION cheesetrap.retention_cleanup(requested_now timestamptz,batch_limit integer) RETURNS TABLE(deleted bigint,protected_events bigint) LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,cheesetrap SET statement_timeout='5s' SET lock_timeout='1s' AS $$
BEGIN
 PERFORM 1 FROM cheesetrap.processing_cursors WHERE singleton FOR UPDATE;
 IF EXISTS(SELECT 1 FROM cheesetrap.evidence_chunks) OR EXISTS(SELECT 1 FROM cheesetrap.detection_results WHERE evidence_representation<>'legacy' OR evidence_state<>'active') THEN RAISE EXCEPTION 'chunk_retention_not_available' USING ERRCODE='23514'; END IF;
 RETURN QUERY SELECT * FROM cheesetrap.retention_cleanup_legacy(requested_now,batch_limit);
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION cheesetrap.retention_cleanup(timestamptz,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION cheesetrap.retention_cleanup(timestamptz,integer) TO cheesetrap_worker;
-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN RAISE EXCEPTION 'evidence_chunks_downgrade_requires_data_preservation'; END $$;
-- +goose StatementEnd
