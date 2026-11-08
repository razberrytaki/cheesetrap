-- +goose Up
ALTER TABLE cheesetrap.reports DROP CONSTRAINT reports_state_check;
ALTER TABLE cheesetrap.reports ADD CONSTRAINT reports_state_check CHECK(state IN ('preparing','held','needs_review','rejected','queued','cancelled','sending'));
CREATE TABLE cheesetrap.approvals (
 approval_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 report_id uuid NOT NULL REFERENCES cheesetrap.reports(report_id),
 revision_id uuid NOT NULL,
 content_digest text NOT NULL CHECK(content_digest ~ '^[0-9a-f]{64}$'),
 admin_id uuid NOT NULL REFERENCES cheesetrap.admins(admin_id),
 mode text NOT NULL DEFAULT 'manual' CHECK(mode='manual'),
 settings_version bigint NOT NULL,
 schedule_version bigint NOT NULL REFERENCES cheesetrap.reporting_schedule_versions(version),
 approved_at timestamptz NOT NULL,
 scheduled_at timestamptz NOT NULL CHECK(scheduled_at>approved_at),
 invalidated_at timestamptz,
 FOREIGN KEY(report_id,revision_id) REFERENCES cheesetrap.report_revisions(report_id,revision_id)
);
CREATE UNIQUE INDEX approvals_active_report ON cheesetrap.approvals(report_id) WHERE invalidated_at IS NULL;
-- +goose StatementBegin
CREATE FUNCTION cheesetrap.preserve_approval() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF (to_jsonb(NEW)-'invalidated_at') IS DISTINCT FROM (to_jsonb(OLD)-'invalidated_at') OR OLD.invalidated_at IS NOT NULL OR NEW.invalidated_at IS NULL THEN
 RAISE EXCEPTION 'approval_immutable' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER approval_immutable BEFORE UPDATE ON cheesetrap.approvals FOR EACH ROW EXECUTE FUNCTION cheesetrap.preserve_approval();
GRANT SELECT,INSERT ON cheesetrap.approvals TO cheesetrap_api,cheesetrap_worker;
GRANT UPDATE(invalidated_at) ON cheesetrap.approvals TO cheesetrap_api,cheesetrap_worker;
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION cheesetrap.preserve_report_pointer() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF (NEW.report_id,NEW.window_id,NEW.source_ip,NEW.created_at,NEW.review_seq) IS DISTINCT FROM (OLD.report_id,OLD.window_id,OLD.source_ip,OLD.created_at,OLD.review_seq)
 OR NEW.version<>OLD.version+1 OR OLD.state IN ('rejected','sending','sent','unknown','closed_unconfirmed')
 THEN RAISE EXCEPTION 'report_revision_pointer_invalid' USING ERRCODE='23514'; END IF;
 IF OLD.state='queued' AND (NEW.state<>'queued' OR NEW.current_revision_id IS DISTINCT FROM OLD.current_revision_id) THEN
  UPDATE cheesetrap.approvals SET invalidated_at=clock_timestamp() WHERE report_id=OLD.report_id AND invalidated_at IS NULL;
 END IF;
 IF NEW.current_revision_id IS NOT DISTINCT FROM OLD.current_revision_id THEN
  IF NOT ((NEW.state='rejected' AND OLD.state IN ('held','needs_review','queued','cancelled') AND NEW.active_refresh_id IS NULL)
   OR (NEW.state='queued' AND OLD.state='needs_review' AND NEW.active_refresh_id IS NULL AND EXISTS(SELECT 1 FROM cheesetrap.approvals a WHERE a.report_id=NEW.report_id AND a.revision_id=NEW.current_revision_id AND a.invalidated_at IS NULL))
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
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION cheesetrap.preserve_report_pointer() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF (NEW.report_id,NEW.window_id,NEW.source_ip,NEW.created_at,NEW.review_seq) IS DISTINCT FROM (OLD.report_id,OLD.window_id,OLD.source_ip,OLD.created_at,OLD.review_seq)
 OR NEW.version<>OLD.version+1 OR OLD.state='rejected'
 THEN RAISE EXCEPTION 'report_revision_pointer_invalid' USING ERRCODE='23514'; END IF;
 IF NEW.current_revision_id IS NOT DISTINCT FROM OLD.current_revision_id THEN
  IF NOT ((NEW.state='rejected' AND OLD.state IN ('held','needs_review') AND NEW.active_refresh_id IS NULL)
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
DROP TABLE cheesetrap.approvals;
DROP FUNCTION cheesetrap.preserve_approval();
ALTER TABLE cheesetrap.reports DROP CONSTRAINT reports_state_check;
ALTER TABLE cheesetrap.reports ADD CONSTRAINT reports_state_check CHECK(state IN ('preparing','held','needs_review','rejected'));
