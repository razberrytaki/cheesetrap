-- +goose Up
CREATE TABLE cheesetrap.automatic_policy (
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
 enabled boolean NOT NULL DEFAULT false,
 version bigint NOT NULL DEFAULT 1,
 settings_version bigint NOT NULL DEFAULT 1,
 effective_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 actor_id uuid REFERENCES cheesetrap.admins(admin_id),
 CHECK(NOT enabled OR actor_id IS NOT NULL)
);
INSERT INTO cheesetrap.automatic_policy(singleton) VALUES(true);
GRANT SELECT ON cheesetrap.automatic_policy TO cheesetrap_api,cheesetrap_worker;
GRANT UPDATE ON cheesetrap.automatic_policy TO cheesetrap_api;
-- SELECT FOR UPDATE needs an UPDATE privilege; workers may lock the singleton
-- but cannot change user-controlled automatic mode or activation provenance.
GRANT UPDATE(singleton) ON cheesetrap.automatic_policy TO cheesetrap_worker;
ALTER TABLE cheesetrap.approvals DROP CONSTRAINT approvals_mode_check;
ALTER TABLE cheesetrap.approvals ADD CONSTRAINT approvals_mode_check CHECK(mode IN ('manual','automatic'));
ALTER TABLE cheesetrap.approvals ADD COLUMN automatic_policy_version bigint;
ALTER TABLE cheesetrap.approvals ADD COLUMN stale_reconfirmed boolean NOT NULL DEFAULT false;
ALTER TABLE cheesetrap.approvals ADD CONSTRAINT automatic_approval_policy CHECK((mode='automatic')=(automatic_policy_version IS NOT NULL));
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION cheesetrap.preserve_report_pointer() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF (NEW.report_id,NEW.window_id,NEW.source_ip,NEW.created_at,NEW.review_seq) IS DISTINCT FROM (OLD.report_id,OLD.window_id,OLD.source_ip,OLD.created_at,OLD.review_seq)
 OR NEW.version<>OLD.version+1 OR OLD.state IN ('rejected','sending','sent','unknown','closed_unconfirmed')
 THEN RAISE EXCEPTION 'report_revision_pointer_invalid' USING ERRCODE='23514'; END IF;
 IF OLD.state='queued' AND (NEW.state NOT IN ('queued','sending') OR NEW.current_revision_id IS DISTINCT FROM OLD.current_revision_id) THEN
  UPDATE cheesetrap.approvals SET invalidated_at=clock_timestamp() WHERE report_id=OLD.report_id AND invalidated_at IS NULL;
 END IF;
 IF NEW.current_revision_id IS NOT DISTINCT FROM OLD.current_revision_id THEN
  IF NOT ((NEW.state='rejected' AND OLD.state IN ('held','needs_review','queued','cancelled') AND NEW.active_refresh_id IS NULL)
   OR (NEW.state='queued' AND OLD.state IN ('needs_review','held') AND NEW.active_refresh_id IS NULL AND EXISTS(SELECT 1 FROM cheesetrap.approvals a WHERE a.report_id=NEW.report_id AND a.revision_id=NEW.current_revision_id AND a.invalidated_at IS NULL))
   OR (NEW.state='needs_review' AND OLD.state='queued' AND NEW.active_refresh_id IS NULL)
   OR (NEW.state='sending' AND OLD.state='queued' AND NEW.active_refresh_id IS NULL AND EXISTS(SELECT 1 FROM cheesetrap.approvals a WHERE a.report_id=NEW.report_id AND a.revision_id=NEW.current_revision_id AND a.invalidated_at IS NULL))
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
-- Approval provenance must not be destroyed by a downgrade.
-- +goose StatementBegin
DO $$ BEGIN RAISE EXCEPTION 'M3-02 downgrade requires an explicit data-preserving migration'; END $$;
-- +goose StatementEnd
