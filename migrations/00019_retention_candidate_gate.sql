-- +goose Up
-- Preserve exact retirement proof, ordering, locks, privileges and batch bounds.
-- Only gate expensive proof by the existing age/window eligibility predicate.
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
 -- Materialize the inexpensive age/window decision before expanding evidence.
 -- Without this barrier PostgreSQL can push membership proof into the root
 -- scan and expand every recent root before consulting its processing event.
 -- Do not limit candidates: protected early roots must not starve later ones.
 SELECT array_agg(detection_id) INTO d_ids FROM (
 WITH candidates AS MATERIALIZED (
 SELECT d.detection_id,d.evidence_state,d.processing_ingestion_seq,d.evidence_count
 FROM cheesetrap.detection_results d JOIN cheesetrap.events e ON e.event_id=d.processing_event_id
 WHERE d.evidence_state='retiring' OR (d.evidence_state='active'
 AND e.ingested_at<at_time-interval '30 days'
 AND EXISTS(SELECT 1 FROM cheesetrap.report_windows w JOIN cheesetrap.report_window_completions c USING(window_id) WHERE e.ingested_at>=w.start_at AND e.ingested_at<w.end_at)))
 SELECT d.detection_id FROM candidates d
 WHERE d.evidence_state='retiring' OR (d.evidence_state='active' AND (SELECT count(*) FROM cheesetrap.detection_evidence_membership m WHERE m.detection_id=d.detection_id)=d.evidence_count
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

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN RAISE EXCEPTION 'retention_candidate_gate_downgrade_requires_review'; END $$;
-- +goose StatementEnd
