-- +goose Up
-- Legacy cleanup before this migration could commit a partial link deletion
-- without recording retirement. Reconcile only those existing, expired legacy
-- roots whose remaining members still have copies and whose window completed.
-- This is a one-time state annotation: immutable proof and links stay untouched.
-- Goose runs this entire migration transactionally. Lock writers/drafters in
-- the usual order; disable only the root guard while the migration owner marks
-- these historical rows, then restore it before installing runtime functions.
-- +goose StatementBegin
DO $$ BEGIN
 PERFORM 1 FROM cheesetrap.processing_cursors WHERE singleton FOR UPDATE;
 PERFORM 1 FROM cheesetrap.report_draft_lock WHERE singleton FOR UPDATE;
END $$;
-- +goose StatementEnd
ALTER TABLE cheesetrap.detection_results DISABLE TRIGGER guard_evidence_root;
UPDATE cheesetrap.detection_results d SET evidence_state='retiring'
FROM cheesetrap.events e
WHERE d.processing_event_id=e.event_id AND d.evidence_representation='legacy' AND d.evidence_state='active'
 AND e.ingested_at<clock_timestamp()-interval '30 days'
 AND (SELECT count(*) FROM cheesetrap.detection_evidence de WHERE de.detection_id=d.detection_id)<d.evidence_count
 AND EXISTS(SELECT 1 FROM cheesetrap.report_windows w JOIN cheesetrap.report_window_completions c USING(window_id) WHERE e.ingested_at>=w.start_at AND e.ingested_at<w.end_at)
 AND NOT EXISTS(SELECT 1 FROM cheesetrap.detection_evidence de WHERE de.detection_id=d.detection_id AND NOT EXISTS(SELECT 1 FROM cheesetrap.report_evidence re WHERE re.event_id=de.event_id));
ALTER TABLE cheesetrap.detection_results ENABLE TRIGGER guard_evidence_root;

-- Retirement is one-way and cleanup-owner-only; runtime grants are unchanged.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION cheesetrap.guard_evidence_root() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,cheesetrap AS $$
BEGIN
 IF TG_OP='INSERT' AND NEW.evidence_state<>'active' THEN RAISE EXCEPTION 'invalid_evidence_state' USING ERRCODE='23514'; END IF;
 IF TG_OP='UPDATE' AND session_user='cheesetrap_worker' AND current_user=pg_get_userbyid((SELECT nspowner FROM pg_namespace WHERE nspname='cheesetrap')) AND OLD.evidence_state='active' AND NEW.evidence_state='retiring' AND (to_jsonb(OLD)-'evidence_state')=(to_jsonb(NEW)-'evidence_state') THEN RETURN NEW; END IF;
 IF TG_OP='UPDATE' THEN RAISE EXCEPTION 'evidence_root_immutable' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION cheesetrap.guard_evidence_membership() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,cheesetrap AS $$
DECLARE c cheesetrap.evidence_chunks; r cheesetrap.detection_results; seq bigint; attached bigint;
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
  SELECT coalesce(sum(h.member_count),0) INTO attached FROM cheesetrap.detection_evidence_chunks d JOIN cheesetrap.evidence_chunks h USING(chunk_id) WHERE d.detection_id=NEW.detection_id;
  IF attached+c.member_count>r.evidence_count OR EXISTS(SELECT 1 FROM cheesetrap.detection_evidence_chunks d JOIN cheesetrap.evidence_chunks h USING(chunk_id) WHERE d.detection_id=NEW.detection_id AND h.bucket_width<>c.bucket_width) THEN RAISE EXCEPTION 'invalid_chunk_attachment' USING ERRCODE='23514'; END IF;
  IF c.retired OR c.bucket_no<>NEW.bucket_no OR r.evidence_representation<>'chunks-v1' OR r.evidence_state<>'active' THEN RAISE EXCEPTION 'invalid_chunk_reference' USING ERRCODE='23514'; END IF;
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION cheesetrap.retention_cleanup(requested_now timestamptz,batch_limit integer)
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
 -- Decide retirement from a complete active set, before deleting any reference.
 -- Resumed roots use the saved decision, never the now-partial membership view.
 SELECT array_agg(detection_id) INTO d_ids FROM (
 SELECT d.detection_id FROM cheesetrap.detection_results d JOIN cheesetrap.events e ON e.event_id=d.processing_event_id
 WHERE d.evidence_state='retiring' OR (d.evidence_state='active'
 AND e.ingested_at<at_time-interval '30 days'
 AND EXISTS(SELECT 1 FROM cheesetrap.report_windows w JOIN cheesetrap.report_window_completions c USING(window_id) WHERE e.ingested_at>=w.start_at AND e.ingested_at<w.end_at)
 AND (SELECT count(*) FROM cheesetrap.detection_evidence_membership m WHERE m.detection_id=d.detection_id)=d.evidence_count
 AND NOT EXISTS(SELECT 1 FROM cheesetrap.detection_evidence_membership m WHERE m.detection_id=d.detection_id AND NOT EXISTS(SELECT 1 FROM cheesetrap.report_evidence re WHERE re.event_id=m.event_id)))
 ORDER BY (d.evidence_state='retiring') DESC,d.processing_ingestion_seq,d.detection_id LIMIT batch_limit) x;
 UPDATE cheesetrap.detection_results SET evidence_state='retiring' WHERE detection_id=ANY(d_ids) AND evidence_state='active';
 DELETE FROM cheesetrap.detection_evidence WHERE (detection_id,event_id) IN (SELECT detection_id,event_id FROM cheesetrap.detection_evidence WHERE detection_id=ANY(d_ids) ORDER BY detection_id,event_id LIMIT batch_limit);
 GET DIAGNOSTICS n=ROW_COUNT;deleted:=deleted+n;
 DELETE FROM cheesetrap.detection_evidence_chunks WHERE (detection_id,bucket_no) IN (SELECT detection_id,bucket_no FROM cheesetrap.detection_evidence_chunks WHERE detection_id=ANY(d_ids) ORDER BY detection_id,bucket_no LIMIT batch_limit);
 GET DIAGNOSTICS n=ROW_COUNT;deleted:=deleted+n;
 DELETE FROM cheesetrap.detection_results d WHERE detection_id=ANY(d_ids) AND evidence_state='retiring' AND NOT EXISTS(SELECT 1 FROM cheesetrap.detection_evidence e WHERE e.detection_id=d.detection_id) AND NOT EXISTS(SELECT 1 FROM cheesetrap.detection_evidence_chunks e WHERE e.detection_id=d.detection_id);
 GET DIAGNOSTICS n=ROW_COUNT;deleted:=deleted+n;
 -- Cursor serialization also covers the writer. Retired partial chunks are
 -- excluded from reuse; active partial-unique identity allows safe replacement.
 UPDATE cheesetrap.evidence_chunks SET retired=true WHERE chunk_id IN (SELECT c.chunk_id FROM cheesetrap.evidence_chunks c WHERE NOT retired AND NOT EXISTS(SELECT 1 FROM cheesetrap.detection_evidence_chunks r WHERE r.chunk_id=c.chunk_id) ORDER BY chunk_id LIMIT batch_limit);
 DELETE FROM cheesetrap.evidence_chunk_members WHERE (chunk_id,event_id) IN (SELECT m.chunk_id,m.event_id FROM cheesetrap.evidence_chunk_members m JOIN cheesetrap.evidence_chunks c USING(chunk_id) WHERE c.retired ORDER BY m.chunk_id,m.event_id LIMIT batch_limit);
 GET DIAGNOSTICS n=ROW_COUNT;deleted:=deleted+n;
 DELETE FROM cheesetrap.evidence_chunks WHERE chunk_id IN (SELECT c.chunk_id FROM cheesetrap.evidence_chunks c WHERE retired AND NOT EXISTS(SELECT 1 FROM cheesetrap.evidence_chunk_members m WHERE m.chunk_id=c.chunk_id) ORDER BY chunk_id LIMIT batch_limit);
 GET DIAGNOSTICS n=ROW_COUNT;deleted:=deleted+n;
 SELECT array_agg(event_id) INTO ids FROM (
 SELECT e.event_id FROM cheesetrap.events e,cheesetrap.processing_cursors c WHERE c.singleton
 AND e.ingested_at<at_time-interval '30 days' AND e.ingestion_seq<=c.detected_seq AND e.ingested_at<c.sealed_before
 AND NOT EXISTS(SELECT 1 FROM cheesetrap.detection_evidence d WHERE d.event_id=e.event_id)
 AND NOT EXISTS(SELECT 1 FROM cheesetrap.evidence_chunk_members m WHERE m.event_id=e.event_id)
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
 DELETE FROM cheesetrap.report_evidence WHERE report_id=rid AND event_id IN (SELECT re.event_id FROM cheesetrap.report_evidence re WHERE report_id=rid AND NOT EXISTS(SELECT 1 FROM cheesetrap.detection_evidence de WHERE de.event_id=re.event_id) AND NOT EXISTS(SELECT 1 FROM cheesetrap.evidence_chunk_members m JOIN cheesetrap.detection_evidence_chunks r USING(chunk_id) WHERE m.event_id=re.event_id) LIMIT batch_limit);
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
 SELECT count(*) INTO protected_events FROM cheesetrap.events e,cheesetrap.processing_cursors c WHERE c.singleton AND e.ingested_at<at_time-interval '30 days' AND (e.ingestion_seq>c.detected_seq OR e.ingested_at>=c.sealed_before OR EXISTS(SELECT 1 FROM cheesetrap.detection_evidence de WHERE de.event_id=e.event_id) OR EXISTS(SELECT 1 FROM cheesetrap.evidence_chunk_members m WHERE m.event_id=e.event_id) OR EXISTS(SELECT 1 FROM cheesetrap.detection_results d WHERE d.processing_event_id=e.event_id));
 UPDATE cheesetrap.retention_status SET protected_events=retention_cleanup.protected_events,checked_at=at_time WHERE singleton;
 RETURN NEXT;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION cheesetrap.retention_cleanup(timestamptz,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION cheesetrap.retention_cleanup(timestamptz,integer) TO cheesetrap_worker;

-- Deferred INSERT checks inspect the final state. Only cleanup can create a
-- retiring state; active roots/chunks retain their original completeness checks.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION cheesetrap.validate_evidence_chunk() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,cheesetrap AS $$
DECLARE c cheesetrap.evidence_chunks; ids uuid[];
BEGIN
 SELECT * INTO c FROM cheesetrap.evidence_chunks WHERE chunk_id=NEW.chunk_id;
 IF NOT FOUND OR c.retired THEN RETURN NULL; END IF;
 SELECT array_agg(event_id ORDER BY event_id) INTO ids FROM cheesetrap.evidence_chunk_members WHERE chunk_id=c.chunk_id;
 IF c.member_count<>coalesce(cardinality(ids),0) OR c.content_hash<>cheesetrap.chunk_content_hash(c.bucket_width,c.bucket_no,ids) THEN RAISE EXCEPTION 'incomplete_evidence_chunk' USING ERRCODE='23514'; END IF;
 RETURN NULL;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION cheesetrap.validate_evidence_root() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,cheesetrap AS $$
DECLARE r cheesetrap.detection_results; n bigint; unique_n bigint; widths bigint; ids uuid[];
BEGIN
 SELECT * INTO r FROM cheesetrap.detection_results WHERE detection_id=NEW.detection_id;
 IF NOT FOUND OR r.evidence_state='retiring' THEN RETURN NULL; END IF;
 IF r.evidence_representation='chunks-v1' THEN
  SELECT count(*),count(DISTINCT m.event_id),count(DISTINCT c.bucket_width),array_agg(m.event_id ORDER BY m.event_id) INTO n,unique_n,widths,ids FROM cheesetrap.detection_evidence_chunks d JOIN cheesetrap.evidence_chunks c USING(chunk_id) JOIN cheesetrap.evidence_chunk_members m USING(chunk_id) WHERE d.detection_id=r.detection_id;
  IF n<>r.evidence_count OR n<>unique_n OR widths<>1 OR r.evidence_hash IS DISTINCT FROM cheesetrap.evidence_set_hash(ids) OR EXISTS(SELECT 1 FROM cheesetrap.detection_evidence WHERE detection_id=r.detection_id) THEN RAISE EXCEPTION 'incomplete_evidence_root' USING ERRCODE='23514'; END IF;
 END IF;
 RETURN NULL;
END $$;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN RAISE EXCEPTION 'chunk_retention_downgrade_requires_data_preservation'; END $$;
-- +goose StatementEnd
