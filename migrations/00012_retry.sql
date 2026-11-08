-- +goose Up
ALTER TABLE cheesetrap.reports DROP CONSTRAINT reports_state_check;
ALTER TABLE cheesetrap.reports ADD CONSTRAINT reports_state_check CHECK(state IN ('preparing','held','needs_review','rejected','queued','cancelled','sending','sent','retry_wait','failed','unknown','closed_unconfirmed'));
-- Approval identity is the retry-group identity; global attempt_number stays report-scoped.
CREATE TABLE cheesetrap.delivery_schedule (
 approval_id uuid PRIMARY KEY REFERENCES cheesetrap.approvals(approval_id),
 due_at timestamptz NOT NULL
);
INSERT INTO cheesetrap.delivery_schedule
SELECT a.approval_id,CASE WHEN r.state='retry_wait' AND d.finished_at IS NOT NULL THEN
 d.finished_at + CASE WHEN d.attempts=1 THEN interval '5 minutes' ELSE interval '30 minutes' END
 + make_interval(secs => (get_byte(sha256(convert_to(a.approval_id::text,'UTF8')),0)%61))
 ELSE a.scheduled_at END
FROM cheesetrap.approvals a JOIN cheesetrap.reports r USING(report_id)
LEFT JOIN LATERAL (SELECT max(finished_at) finished_at,count(*) attempts FROM cheesetrap.delivery_attempts WHERE approval_id=a.approval_id) d ON true;
-- +goose StatementBegin
CREATE FUNCTION cheesetrap.initialize_delivery_schedule() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 INSERT INTO cheesetrap.delivery_schedule(approval_id,due_at) VALUES(NEW.approval_id,NEW.scheduled_at);
 RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER approval_delivery_schedule AFTER INSERT ON cheesetrap.approvals FOR EACH ROW EXECUTE FUNCTION cheesetrap.initialize_delivery_schedule();
GRANT SELECT,INSERT ON cheesetrap.delivery_schedule TO cheesetrap_api,cheesetrap_worker;
GRANT UPDATE(due_at) ON cheesetrap.delivery_schedule TO cheesetrap_worker;
-- Attempts ARE quota reservations. Every historical result, including unknown,
-- counts without a counter backfill or migration-induced reset.
CREATE INDEX delivery_attempt_quota_day ON cheesetrap.delivery_attempts(started_at);
ALTER TABLE cheesetrap.reports ADD COLUMN delivery_uncertain boolean NOT NULL DEFAULT false;
-- Legacy sending/unknown boundaries may predate attempt records.
ALTER TABLE cheesetrap.reports DISABLE TRIGGER preserve_report_pointer;
UPDATE cheesetrap.reports SET delivery_uncertain=true WHERE state='unknown' OR EXISTS(SELECT 1 FROM cheesetrap.delivery_attempts d WHERE d.report_id=reports.report_id AND d.result='unknown');
UPDATE cheesetrap.reports r SET state='failed',version=version+1 WHERE state='retry_wait' AND EXISTS(SELECT 1 FROM cheesetrap.approvals a WHERE a.report_id=r.report_id AND a.invalidated_at IS NULL AND (SELECT count(*) FROM cheesetrap.delivery_attempts WHERE approval_id=a.approval_id)>=3);
ALTER TABLE cheesetrap.reports ENABLE TRIGGER preserve_report_pointer;
CREATE TABLE cheesetrap.delivery_closures (
 report_id uuid PRIMARY KEY REFERENCES cheesetrap.reports(report_id),
 admin_id uuid NOT NULL REFERENCES cheesetrap.admins(admin_id),
 reason text NOT NULL CHECK(length(btrim(reason)) BETWEEN 1 AND 2000),
 closed_at timestamptz NOT NULL,
 retention_until timestamptz NOT NULL CHECK(retention_until=closed_at+interval '180 days'),
 retention_basis text NOT NULL DEFAULT 'closure' CHECK(retention_basis='closure')
);
GRANT SELECT,INSERT ON cheesetrap.delivery_closures TO cheesetrap_api;
GRANT SELECT ON cheesetrap.delivery_closures TO cheesetrap_worker;
CREATE TRIGGER closure_no_update BEFORE UPDATE ON cheesetrap.delivery_closures FOR EACH ROW EXECUTE FUNCTION cheesetrap.immutable_report_record();
CREATE TRIGGER closure_no_delete BEFORE DELETE ON cheesetrap.delivery_closures FOR EACH ROW EXECUTE FUNCTION cheesetrap.immutable_report_record();
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION cheesetrap.preserve_report_pointer() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 NEW.delivery_uncertain := OLD.delivery_uncertain OR NEW.state='unknown';
 IF (NEW.report_id,NEW.window_id,NEW.source_ip,NEW.created_at,NEW.review_seq) IS DISTINCT FROM (OLD.report_id,OLD.window_id,OLD.source_ip,OLD.created_at,OLD.review_seq)
 OR NEW.version<>OLD.version+1 OR OLD.state IN ('rejected','sent','closed_unconfirmed')
 THEN RAISE EXCEPTION 'report_revision_pointer_invalid' USING ERRCODE='23514'; END IF;
 IF OLD.state IN ('queued','retry_wait','failed','unknown') AND (NEW.state NOT IN ('queued','sending','retry_wait') OR NEW.current_revision_id IS DISTINCT FROM OLD.current_revision_id) THEN
  UPDATE cheesetrap.approvals SET invalidated_at=clock_timestamp() WHERE report_id=OLD.report_id AND invalidated_at IS NULL;
 END IF;
 IF OLD.state='sending' AND (NEW.current_revision_id IS DISTINCT FROM OLD.current_revision_id OR NEW.state NOT IN ('sent','retry_wait','failed','unknown')) THEN RAISE EXCEPTION 'sending_revision_immutable' USING ERRCODE='23514'; END IF;
 IF NEW.current_revision_id IS NOT DISTINCT FROM OLD.current_revision_id THEN
  IF NOT ((NEW.state='closed_unconfirmed' AND OLD.state IN ('unknown','failed','held','needs_review') AND NEW.delivery_uncertain AND NEW.active_refresh_id IS NULL AND EXISTS(SELECT 1 FROM cheesetrap.delivery_closures c WHERE c.report_id=NEW.report_id))
   OR (NEW.state='rejected' AND NOT OLD.delivery_uncertain AND OLD.state IN ('held','needs_review','queued','cancelled') AND NEW.active_refresh_id IS NULL)
   OR (NEW.state='queued' AND OLD.state IN ('needs_review','held','failed','unknown','retry_wait') AND NEW.active_refresh_id IS NULL AND EXISTS(SELECT 1 FROM cheesetrap.approvals a WHERE a.report_id=NEW.report_id AND a.revision_id=NEW.current_revision_id AND a.invalidated_at IS NULL))
   OR (NEW.state='needs_review' AND OLD.state IN ('queued','retry_wait','failed','unknown') AND NEW.active_refresh_id IS NULL)
   OR (NEW.state='sending' AND OLD.state IN ('queued','retry_wait') AND NEW.active_refresh_id IS NULL AND EXISTS(SELECT 1 FROM cheesetrap.approvals a WHERE a.report_id=NEW.report_id AND a.revision_id=NEW.current_revision_id AND a.invalidated_at IS NULL))
   OR (OLD.state='sending' AND NEW.state IN ('sent','retry_wait','failed','unknown') AND NEW.active_refresh_id IS NULL AND (NEW.state='unknown' OR EXISTS(SELECT 1 FROM cheesetrap.delivery_attempts d WHERE d.report_id=NEW.report_id AND d.revision_id=NEW.current_revision_id AND d.result=NEW.state)))
   OR (NEW.state='cancelled' AND OLD.state IN ('queued','retry_wait') AND NEW.active_refresh_id IS NULL)
   OR (NEW.state='needs_review' AND OLD.state IN ('queued','retry_wait','failed','unknown') AND NEW.active_refresh_id IS NOT NULL AND EXISTS(SELECT 1 FROM cheesetrap.contact_refresh_requests f WHERE f.request_id=NEW.active_refresh_id AND f.report_id=NEW.report_id AND f.revision_id=NEW.current_revision_id AND f.expected_version=NEW.version AND f.status='queued'))
   OR (NEW.state=OLD.state AND NEW.state IN ('held','needs_review') AND NEW.active_refresh_id IS DISTINCT FROM OLD.active_refresh_id
    AND (NEW.active_refresh_id IS NULL OR EXISTS(SELECT 1 FROM cheesetrap.contact_refresh_requests f WHERE f.request_id=NEW.active_refresh_id AND f.report_id=NEW.report_id AND f.revision_id=NEW.current_revision_id AND f.expected_version=NEW.version AND f.status='queued'))))
  THEN RAISE EXCEPTION 'report_state_transition_invalid' USING ERRCODE='23514'; END IF;
 ELSE
  IF NEW.active_refresh_id IS NOT NULL OR NOT EXISTS(SELECT 1 FROM cheesetrap.report_revisions v WHERE v.report_id=NEW.report_id AND v.revision_id=NEW.current_revision_id AND v.version=NEW.version AND v.state=NEW.state)
  THEN RAISE EXCEPTION 'report_revision_pointer_invalid' USING ERRCODE='23514'; END IF;
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN RAISE EXCEPTION 'M3-04 downgrade requires an explicit data-preserving migration'; END $$;
-- +goose StatementEnd
