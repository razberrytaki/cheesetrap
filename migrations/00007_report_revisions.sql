-- +goose Up
CREATE TABLE cheesetrap.report_draft_lock (singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton));
INSERT INTO cheesetrap.report_draft_lock VALUES(true);
CREATE TABLE cheesetrap.report_window_completions (
 window_id uuid PRIMARY KEY REFERENCES cheesetrap.report_windows(window_id),
 completed_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE cheesetrap.reports (
 report_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 window_id uuid NOT NULL REFERENCES cheesetrap.report_windows(window_id),
 source_ip inet NOT NULL,
 version bigint NOT NULL DEFAULT 0 CHECK(version>=0),
 current_revision_id uuid,
 state text NOT NULL DEFAULT 'preparing' CHECK(state IN ('preparing','needs_review','held')),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(window_id,source_ip),
 CHECK(masklen(source_ip)=CASE family(source_ip) WHEN 4 THEN 32 ELSE 128 END),
 CHECK((version=0 AND current_revision_id IS NULL AND state='preparing') OR (version>0 AND current_revision_id IS NOT NULL AND state<>'preparing'))
);
CREATE TABLE cheesetrap.report_candidates (
 window_id uuid NOT NULL REFERENCES cheesetrap.report_windows(window_id),
 source_ip inet NOT NULL,
 outcome text NOT NULL CHECK(outcome IN ('created','already_assigned')),
 report_id uuid REFERENCES cheesetrap.reports(report_id),
 PRIMARY KEY(window_id,source_ip),
 CHECK((outcome='created')=(report_id IS NOT NULL))
);
-- No FK to events/detections: their retention cannot erase immutable evidence.
CREATE TABLE cheesetrap.report_evidence (
 event_id uuid PRIMARY KEY,
 report_id uuid NOT NULL REFERENCES cheesetrap.reports(report_id),
 snapshot jsonb NOT NULL CHECK(jsonb_typeof(snapshot)='object'),
 UNIQUE(report_id,event_id)
);
CREATE TABLE cheesetrap.report_revisions (
 revision_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 report_id uuid NOT NULL REFERENCES cheesetrap.reports(report_id),
 version bigint NOT NULL CHECK(version>0),
 snapshot jsonb NOT NULL CHECK(jsonb_typeof(snapshot)='object'),
 subject text NOT NULL CHECK(length(subject)>0 AND subject !~ E'[\\r\\n]'),
 body text NOT NULL CHECK(octet_length(body) BETWEEN 1 AND 1048576),
 recipient text NOT NULL CHECK(recipient !~ E'[\\r\\n]'),
 reply_to text NOT NULL CHECK(reply_to !~ E'[\\r\\n]'),
 hold_reasons text[] NOT NULL,
 state text NOT NULL CHECK(state IN ('needs_review','held')),
 auto_approval_allowed boolean NOT NULL,
 body_edited boolean NOT NULL,
 content_digest text NOT NULL CHECK(content_digest ~ '^[a-f0-9]{64}$'),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(report_id,version),
 UNIQUE(report_id,revision_id),
 CHECK((state='held')=(cardinality(hold_reasons)>0))
);
ALTER TABLE cheesetrap.reports ADD CONSTRAINT report_current_revision_owner
 FOREIGN KEY(report_id,current_revision_id) REFERENCES cheesetrap.report_revisions(report_id,revision_id) DEFERRABLE INITIALLY DEFERRED;
-- +goose StatementBegin
CREATE FUNCTION cheesetrap.immutable_report_record() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'report_record_immutable' USING ERRCODE='23514'; END $$;
-- +goose StatementEnd
CREATE TRIGGER immutable_report_evidence BEFORE UPDATE OR DELETE ON cheesetrap.report_evidence FOR EACH ROW EXECUTE FUNCTION cheesetrap.immutable_report_record();
CREATE TRIGGER immutable_report_revision BEFORE UPDATE OR DELETE ON cheesetrap.report_revisions FOR EACH ROW EXECUTE FUNCTION cheesetrap.immutable_report_record();
CREATE TRIGGER immutable_report_candidate BEFORE UPDATE OR DELETE ON cheesetrap.report_candidates FOR EACH ROW EXECUTE FUNCTION cheesetrap.immutable_report_record();
CREATE TRIGGER immutable_report_completion BEFORE UPDATE OR DELETE ON cheesetrap.report_window_completions FOR EACH ROW EXECUTE FUNCTION cheesetrap.immutable_report_record();
GRANT SELECT,UPDATE ON cheesetrap.report_draft_lock TO cheesetrap_worker;
GRANT SELECT,INSERT ON cheesetrap.report_window_completions,cheesetrap.report_candidates TO cheesetrap_worker;
GRANT SELECT ON cheesetrap.reports,cheesetrap.report_evidence,cheesetrap.report_revisions TO cheesetrap_api,cheesetrap_worker;
GRANT INSERT ON cheesetrap.reports,cheesetrap.report_evidence TO cheesetrap_worker;
GRANT INSERT ON cheesetrap.report_revisions TO cheesetrap_api,cheesetrap_worker;
GRANT UPDATE(version,current_revision_id,state) ON cheesetrap.reports TO cheesetrap_api,cheesetrap_worker;
GRANT SELECT ON cheesetrap.settings TO cheesetrap_worker;

-- +goose StatementBegin
CREATE FUNCTION cheesetrap.preserve_report_pointer() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF (NEW.report_id,NEW.window_id,NEW.source_ip,NEW.created_at) IS DISTINCT FROM (OLD.report_id,OLD.window_id,OLD.source_ip,OLD.created_at)
 OR NEW.version<>OLD.version+1
 OR NOT EXISTS(SELECT 1 FROM cheesetrap.report_revisions v WHERE v.report_id=NEW.report_id AND v.revision_id=NEW.current_revision_id AND v.version=NEW.version AND v.state=NEW.state)
 THEN RAISE EXCEPTION 'report_revision_pointer_invalid' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER preserve_report_pointer BEFORE UPDATE ON cheesetrap.reports FOR EACH ROW EXECUTE FUNCTION cheesetrap.preserve_report_pointer();

-- +goose Down
ALTER TABLE cheesetrap.reports DROP CONSTRAINT report_current_revision_owner;
DROP TABLE cheesetrap.report_revisions,cheesetrap.report_evidence,cheesetrap.report_candidates,cheesetrap.reports,cheesetrap.report_window_completions,cheesetrap.report_draft_lock;
DROP FUNCTION cheesetrap.immutable_report_record(),cheesetrap.preserve_report_pointer();
REVOKE SELECT ON cheesetrap.settings FROM cheesetrap_worker;
