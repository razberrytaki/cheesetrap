-- +goose Up
ALTER TABLE cheesetrap.reports DROP CONSTRAINT reports_state_check;
ALTER TABLE cheesetrap.reports ADD CONSTRAINT reports_state_check CHECK(state IN ('preparing','held','needs_review','rejected','queued','cancelled','sending','sent','retry_wait','failed','unknown'));
CREATE TABLE cheesetrap.delivery_attempts (
 attempt_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 report_id uuid NOT NULL REFERENCES cheesetrap.reports(report_id),
 revision_id uuid NOT NULL,
 approval_id uuid NOT NULL REFERENCES cheesetrap.approvals(approval_id),
 attempt_number integer NOT NULL CHECK(attempt_number>0),
 message_id text NOT NULL CHECK(length(message_id)<=100),
 phase text NOT NULL CHECK(phase IN ('started','prepare','connect','tls','greeting','auth','mail','rcpt','data','response','recovery')),
 result text NOT NULL CHECK(result IN ('sending','sent','retry_wait','failed','unknown')),
 classification text NOT NULL CHECK(classification IN ('smtp_started','smtp_message_invalid','smtp_transport_failed','smtp_acceptance_unknown','smtp_temporary_refusal','smtp_permanent_refusal','smtp_certificate_invalid','smtp_tls_required','smtp_auth_required','smtp_accepted','smtp_interrupted')),
 smtp_code integer CHECK(smtp_code BETWEEN 200 AND 599),
 started_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 finished_at timestamptz,
 FOREIGN KEY(report_id,revision_id) REFERENCES cheesetrap.report_revisions(report_id,revision_id),
 UNIQUE(report_id,attempt_number),
 CHECK((result='sending')=(finished_at IS NULL)),
 CHECK(finished_at IS NULL OR finished_at>=started_at)
);
CREATE UNIQUE INDEX delivery_attempt_unresolved ON cheesetrap.delivery_attempts(report_id) WHERE result='sending';
CREATE INDEX delivery_attempt_approval ON cheesetrap.delivery_attempts(approval_id);
-- +goose StatementBegin
CREATE FUNCTION cheesetrap.preserve_delivery_attempt() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF (to_jsonb(NEW)-ARRAY['phase','result','classification','smtp_code','finished_at']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['phase','result','classification','smtp_code','finished_at']) OR OLD.result<>'sending' OR NEW.result='sending' THEN
  RAISE EXCEPTION 'delivery_attempt_immutable' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER delivery_attempt_immutable BEFORE UPDATE ON cheesetrap.delivery_attempts FOR EACH ROW EXECUTE FUNCTION cheesetrap.preserve_delivery_attempt();
CREATE TRIGGER delivery_attempt_no_delete BEFORE DELETE ON cheesetrap.delivery_attempts FOR EACH ROW EXECUTE FUNCTION cheesetrap.immutable_report_record();
GRANT SELECT ON cheesetrap.delivery_attempts TO cheesetrap_api,cheesetrap_worker;
GRANT INSERT ON cheesetrap.delivery_attempts TO cheesetrap_worker;
GRANT UPDATE(phase,result,classification,smtp_code,finished_at) ON cheesetrap.delivery_attempts TO cheesetrap_worker;
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION cheesetrap.preserve_report_pointer() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF (NEW.report_id,NEW.window_id,NEW.source_ip,NEW.created_at,NEW.review_seq) IS DISTINCT FROM (OLD.report_id,OLD.window_id,OLD.source_ip,OLD.created_at,OLD.review_seq)
 OR NEW.version<>OLD.version+1 OR OLD.state IN ('rejected','sent','unknown','closed_unconfirmed','retry_wait','failed')
 THEN RAISE EXCEPTION 'report_revision_pointer_invalid' USING ERRCODE='23514'; END IF;
 IF OLD.state='queued' AND (NEW.state NOT IN ('queued','sending') OR NEW.current_revision_id IS DISTINCT FROM OLD.current_revision_id) THEN
  UPDATE cheesetrap.approvals SET invalidated_at=clock_timestamp() WHERE report_id=OLD.report_id AND invalidated_at IS NULL;
 END IF;
 IF OLD.state='sending' AND (NEW.current_revision_id IS DISTINCT FROM OLD.current_revision_id OR NEW.state NOT IN ('sent','retry_wait','failed','unknown')) THEN RAISE EXCEPTION 'sending_revision_immutable' USING ERRCODE='23514'; END IF;
 IF NEW.current_revision_id IS NOT DISTINCT FROM OLD.current_revision_id THEN
  IF NOT ((NEW.state='rejected' AND OLD.state IN ('held','needs_review','queued','cancelled') AND NEW.active_refresh_id IS NULL)
   OR (NEW.state='queued' AND OLD.state IN ('needs_review','held') AND NEW.active_refresh_id IS NULL AND EXISTS(SELECT 1 FROM cheesetrap.approvals a WHERE a.report_id=NEW.report_id AND a.revision_id=NEW.current_revision_id AND a.invalidated_at IS NULL))
   OR (NEW.state='needs_review' AND OLD.state='queued' AND NEW.active_refresh_id IS NULL)
   OR (NEW.state='sending' AND OLD.state='queued' AND NEW.active_refresh_id IS NULL AND EXISTS(SELECT 1 FROM cheesetrap.approvals a WHERE a.report_id=NEW.report_id AND a.revision_id=NEW.current_revision_id AND a.invalidated_at IS NULL))
   OR (OLD.state='sending' AND NEW.state IN ('sent','retry_wait','failed','unknown') AND NEW.active_refresh_id IS NULL AND (NEW.state='unknown' OR EXISTS(SELECT 1 FROM cheesetrap.delivery_attempts d WHERE d.report_id=NEW.report_id AND d.revision_id=NEW.current_revision_id AND d.result=NEW.state)))
   OR (NEW.state='cancelled' AND OLD.state='queued' AND NEW.active_refresh_id IS NULL)
   OR (NEW.state='needs_review' AND OLD.state='queued' AND NEW.active_refresh_id IS NOT NULL AND EXISTS(SELECT 1 FROM cheesetrap.contact_refresh_requests f WHERE f.request_id=NEW.active_refresh_id AND f.report_id=NEW.report_id AND f.revision_id=NEW.current_revision_id AND f.expected_version=NEW.version AND f.status='queued'))
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
-- Delivery outcomes and uncertain attempts must not be discarded.
-- +goose StatementBegin
DO $$ BEGIN RAISE EXCEPTION 'M3-03 downgrade requires an explicit data-preserving migration'; END $$;
-- +goose StatementEnd
