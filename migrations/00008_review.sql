-- +goose Up
ALTER TABLE cheesetrap.reports DROP CONSTRAINT reports_state_check;
ALTER TABLE cheesetrap.reports ADD CONSTRAINT reports_state_check CHECK(state IN ('preparing','needs_review','held','rejected'));
ALTER TABLE cheesetrap.reports ADD COLUMN review_seq bigint GENERATED ALWAYS AS IDENTITY;
CREATE UNIQUE INDEX reports_review_seq_idx ON cheesetrap.reports(review_seq);
CREATE INDEX reports_source_review_idx ON cheesetrap.reports(source_ip,review_seq DESC);
ALTER TABLE cheesetrap.reports ADD COLUMN active_refresh_id uuid;
CREATE TABLE cheesetrap.review_idempotency (
 admin_id uuid NOT NULL REFERENCES cheesetrap.admins(admin_id),
 key text NOT NULL CHECK(octet_length(key) BETWEEN 1 AND 128 AND key ~ '^[!-~]+$'),
 request_hash text NOT NULL CHECK(request_hash ~ '^[a-f0-9]{64}$'),
 status integer NOT NULL CHECK(status IN (200,202)),
 response bytea NOT NULL CHECK(octet_length(response)<=1048576),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(admin_id,key)
);
CREATE TRIGGER immutable_review_idempotency BEFORE UPDATE OR DELETE ON cheesetrap.review_idempotency FOR EACH ROW EXECUTE FUNCTION cheesetrap.immutable_report_record();
CREATE TABLE cheesetrap.rule_config_versions (
 settings_version bigint PRIMARY KEY CHECK(settings_version>0),
 effective_from_seq bigint NOT NULL CHECK(effective_from_seq>0),
 config jsonb NOT NULL CHECK(jsonb_typeof(config)='object'),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
INSERT INTO cheesetrap.rule_config_versions VALUES(1,1,'{"ssh_repeat_threshold":10,"web_repeat_threshold":20,"web_distinct_path_threshold":5}',clock_timestamp());
CREATE INDEX rule_config_effective_idx ON cheesetrap.rule_config_versions(effective_from_seq DESC,settings_version DESC);
CREATE TRIGGER immutable_rule_config BEFORE UPDATE OR DELETE ON cheesetrap.rule_config_versions FOR EACH ROW EXECUTE FUNCTION cheesetrap.immutable_report_record();
INSERT INTO cheesetrap.settings(key,version,value)
 SELECT 'review_policy',1,jsonb_build_object('reply_to',coalesce((SELECT value->>'address' FROM cheesetrap.settings WHERE key='reporting_reply_to'),''),
 'timezone',s.timezone,'period_days',s.period_days,'schedule_version',s.version::text,'rule_effective_from_seq','1',
 'rules',(SELECT config FROM cheesetrap.rule_config_versions WHERE settings_version=1))
 FROM cheesetrap.reporting_schedule_versions s ORDER BY version DESC LIMIT 1;
ALTER TABLE cheesetrap.detection_results ADD COLUMN settings_version bigint NOT NULL DEFAULT 1 REFERENCES cheesetrap.rule_config_versions(settings_version);
ALTER TABLE cheesetrap.detection_completions ADD COLUMN settings_version bigint NOT NULL DEFAULT 1 REFERENCES cheesetrap.rule_config_versions(settings_version);
ALTER TABLE cheesetrap.detection_results ADD COLUMN review_seq bigint GENERATED ALWAYS AS IDENTITY;
CREATE INDEX detection_source_review_idx ON cheesetrap.detection_results(source_ip,review_seq DESC);
CREATE TABLE cheesetrap.contact_refresh_requests (
 request_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 report_id uuid NOT NULL REFERENCES cheesetrap.reports(report_id),
 expected_version bigint NOT NULL CHECK(expected_version>0),
 revision_id uuid NOT NULL,
 settings_version bigint NOT NULL REFERENCES cheesetrap.rule_config_versions(settings_version),
 admin_id uuid NOT NULL REFERENCES cheesetrap.admins(admin_id),
 status text NOT NULL DEFAULT 'queued' CHECK(status IN ('queued','completed','superseded')),
 result_revision_id uuid,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 completed_at timestamptz,
 UNIQUE(report_id,request_id),
 FOREIGN KEY(report_id,revision_id) REFERENCES cheesetrap.report_revisions(report_id,revision_id),
 FOREIGN KEY(report_id,result_revision_id) REFERENCES cheesetrap.report_revisions(report_id,revision_id),
 CHECK((status='queued')=(completed_at IS NULL)),
 CHECK((status='completed')=(result_revision_id IS NOT NULL))
);
CREATE INDEX refresh_requests_queued_idx ON cheesetrap.contact_refresh_requests(created_at,request_id) WHERE status='queued';
CREATE INDEX refresh_requests_report_idx ON cheesetrap.contact_refresh_requests(report_id,created_at DESC,request_id DESC);
ALTER TABLE cheesetrap.reports ADD CONSTRAINT report_active_refresh_owner FOREIGN KEY(report_id,active_refresh_id) REFERENCES cheesetrap.contact_refresh_requests(report_id,request_id) DEFERRABLE INITIALLY DEFERRED;
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
GRANT SELECT,INSERT ON cheesetrap.review_idempotency TO cheesetrap_api;
GRANT SELECT,INSERT ON cheesetrap.rule_config_versions TO cheesetrap_api;
GRANT SELECT ON cheesetrap.rule_config_versions TO cheesetrap_worker;
GRANT SELECT,INSERT,UPDATE ON cheesetrap.contact_refresh_requests TO cheesetrap_api,cheesetrap_worker;
GRANT UPDATE(active_refresh_id) ON cheesetrap.reports TO cheesetrap_api,cheesetrap_worker;
GRANT INSERT ON cheesetrap.audit TO cheesetrap_worker;
GRANT SELECT ON cheesetrap.processing_cursors,cheesetrap.reporting_schedule_cursor,cheesetrap.reporting_schedule_versions,cheesetrap.report_windows TO cheesetrap_api;
GRANT UPDATE(sealed_before) ON cheesetrap.processing_cursors TO cheesetrap_api;
GRANT UPDATE(next_start) ON cheesetrap.reporting_schedule_cursor TO cheesetrap_api;
GRANT INSERT ON cheesetrap.reporting_schedule_versions TO cheesetrap_api;
GRANT USAGE ON SEQUENCE cheesetrap.reporting_schedule_versions_version_seq TO cheesetrap_api;

-- +goose Down
ALTER TABLE cheesetrap.reports DROP CONSTRAINT report_active_refresh_owner;
DROP TABLE cheesetrap.contact_refresh_requests,cheesetrap.review_idempotency;
ALTER TABLE cheesetrap.detection_results DROP COLUMN settings_version,DROP COLUMN review_seq;
ALTER TABLE cheesetrap.detection_completions DROP COLUMN settings_version;
DROP TABLE cheesetrap.rule_config_versions;
DELETE FROM cheesetrap.settings WHERE key='review_policy';
ALTER TABLE cheesetrap.reports DROP COLUMN active_refresh_id,DROP COLUMN review_seq;
ALTER TABLE cheesetrap.reports DROP CONSTRAINT reports_state_check;
ALTER TABLE cheesetrap.reports ADD CONSTRAINT reports_state_check CHECK(state IN ('preparing','needs_review','held'));
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION cheesetrap.preserve_report_pointer() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF (NEW.report_id,NEW.window_id,NEW.source_ip,NEW.created_at) IS DISTINCT FROM (OLD.report_id,OLD.window_id,OLD.source_ip,OLD.created_at)
 OR NEW.version<>OLD.version+1
 OR NOT EXISTS(SELECT 1 FROM cheesetrap.report_revisions v WHERE v.report_id=NEW.report_id AND v.revision_id=NEW.current_revision_id AND v.version=NEW.version AND v.state=NEW.state)
 THEN RAISE EXCEPTION 'report_revision_pointer_invalid' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE INSERT ON cheesetrap.audit FROM cheesetrap_worker;
REVOKE UPDATE(sealed_before) ON cheesetrap.processing_cursors FROM cheesetrap_api;
REVOKE UPDATE(next_start) ON cheesetrap.reporting_schedule_cursor FROM cheesetrap_api;
REVOKE INSERT ON cheesetrap.reporting_schedule_versions FROM cheesetrap_api;
REVOKE USAGE ON SEQUENCE cheesetrap.reporting_schedule_versions_version_seq FROM cheesetrap_api;
REVOKE SELECT ON cheesetrap.reporting_schedule_cursor,cheesetrap.reporting_schedule_versions,cheesetrap.report_windows FROM cheesetrap_api;
