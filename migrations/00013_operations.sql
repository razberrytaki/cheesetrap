-- +goose Up
CREATE TABLE cheesetrap.smtp_tests (
 test_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 recipient text NOT NULL CHECK(length(recipient)<=254),
 status text NOT NULL DEFAULT 'queued' CHECK(status IN ('queued','sending','sent','failed','unknown','unavailable','quota_exceeded')),
 classification text NOT NULL DEFAULT '',
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 started_at timestamptz,
 finished_at timestamptz,
 CHECK((status IN ('sending','sent','failed','unknown'))=(started_at IS NOT NULL)),
 CHECK((status NOT IN ('queued','sending'))=(finished_at IS NOT NULL)),
 CHECK(finished_at IS NULL OR finished_at>=coalesce(started_at,created_at))
);
-- +goose StatementBegin
CREATE FUNCTION cheesetrap.preserve_smtp_test() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF (NEW.test_id,NEW.recipient,NEW.created_at) IS DISTINCT FROM (OLD.test_id,OLD.recipient,OLD.created_at)
 OR NOT ((OLD.status='queued' AND NEW.status IN ('sending','unavailable','quota_exceeded')) OR (OLD.status='sending' AND NEW.status IN ('sent','failed','unknown')))
 OR (OLD.started_at IS NOT NULL AND NEW.started_at IS DISTINCT FROM OLD.started_at)
 THEN RAISE EXCEPTION 'smtp_test_immutable' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER smtp_test_immutable BEFORE UPDATE ON cheesetrap.smtp_tests FOR EACH ROW EXECUTE FUNCTION cheesetrap.preserve_smtp_test();
CREATE TRIGGER smtp_test_no_delete BEFORE DELETE ON cheesetrap.smtp_tests FOR EACH ROW EXECUTE FUNCTION cheesetrap.immutable_report_record();
GRANT SELECT ON cheesetrap.smtp_tests TO cheesetrap_api,cheesetrap_worker;
GRANT INSERT(test_id,recipient) ON cheesetrap.smtp_tests TO cheesetrap_api;
GRANT UPDATE(status,classification,started_at,finished_at) ON cheesetrap.smtp_tests TO cheesetrap_worker;
CREATE INDEX smtp_tests_quota ON cheesetrap.smtp_tests(started_at) WHERE started_at IS NOT NULL;
-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN RAISE EXCEPTION 'SMTP test audit records require data-preserving migration'; END $$;
-- +goose StatementEnd
