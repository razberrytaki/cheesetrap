-- +goose Up
ALTER TABLE cheesetrap.processing_cursors ADD COLUMN sealed_before timestamptz NOT NULL DEFAULT '-infinity';
GRANT UPDATE(sealed_before) ON cheesetrap.processing_cursors TO cheesetrap_worker;
CREATE TABLE cheesetrap.reporting_schedule_versions (
 version bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 timezone text NOT NULL CHECK(length(timezone) BETWEEN 1 AND 100),
 period_days integer NOT NULL CHECK(period_days BETWEEN 1 AND 31),
 effective_from timestamptz NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
INSERT INTO cheesetrap.reporting_schedule_versions(timezone,period_days,effective_from) VALUES('UTC',1,'-infinity');
CREATE INDEX reporting_schedule_effective_idx ON cheesetrap.reporting_schedule_versions(effective_from DESC,version DESC);
CREATE TABLE cheesetrap.reporting_schedule_cursor (
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
 next_start timestamptz
);
INSERT INTO cheesetrap.reporting_schedule_cursor(singleton) VALUES(true);
CREATE TABLE cheesetrap.report_windows (
 window_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 start_at timestamptz NOT NULL UNIQUE,
 end_at timestamptz NOT NULL CHECK(end_at>start_at),
 settings_version bigint NOT NULL REFERENCES cheesetrap.reporting_schedule_versions(version),
 state text NOT NULL DEFAULT 'open' CHECK(state IN ('open','sealed','ready')),
 sealed_seq bigint CHECK(sealed_seq>=0),
 sealed_at timestamptz,
 ready_at timestamptz,
 CHECK((state='open' AND sealed_seq IS NULL AND sealed_at IS NULL AND ready_at IS NULL) OR
       (state='sealed' AND sealed_seq IS NOT NULL AND sealed_at IS NOT NULL AND ready_at IS NULL) OR
       (state='ready' AND sealed_seq IS NOT NULL AND sealed_at IS NOT NULL AND ready_at IS NOT NULL))
);
CREATE INDEX report_windows_pending_idx ON cheesetrap.report_windows(start_at) WHERE state<>'ready';
GRANT SELECT,INSERT ON cheesetrap.reporting_schedule_versions TO cheesetrap_worker;
GRANT USAGE ON SEQUENCE cheesetrap.reporting_schedule_versions_version_seq TO cheesetrap_worker;
GRANT SELECT ON cheesetrap.reporting_schedule_cursor,cheesetrap.report_windows TO cheesetrap_worker;
GRANT UPDATE(next_start) ON cheesetrap.reporting_schedule_cursor TO cheesetrap_worker;
GRANT INSERT ON cheesetrap.report_windows TO cheesetrap_worker;
GRANT UPDATE(state,sealed_seq,sealed_at,ready_at) ON cheesetrap.report_windows TO cheesetrap_worker;

-- +goose StatementBegin
CREATE FUNCTION cheesetrap.preserve_report_window() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF (NEW.window_id,NEW.start_at,NEW.end_at,NEW.settings_version) IS DISTINCT FROM (OLD.window_id,OLD.start_at,OLD.end_at,OLD.settings_version)
 OR (OLD.state<>'open' AND (NEW.sealed_seq,NEW.sealed_at) IS DISTINCT FROM (OLD.sealed_seq,OLD.sealed_at))
 OR (OLD.state='ready' AND NEW IS DISTINCT FROM OLD)
 OR (OLD.state='sealed' AND NEW.state NOT IN ('sealed','ready'))
 OR (NEW.state='ready' AND NEW.sealed_seq>(SELECT detected_seq FROM cheesetrap.processing_cursors WHERE singleton))
 THEN RAISE EXCEPTION 'report_window_immutable_or_unready' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER preserve_report_window BEFORE UPDATE ON cheesetrap.report_windows FOR EACH ROW EXECUTE FUNCTION cheesetrap.preserve_report_window();

-- +goose Down
DROP TABLE cheesetrap.report_windows;
DROP FUNCTION cheesetrap.preserve_report_window();
DROP TABLE cheesetrap.reporting_schedule_cursor;
DROP TABLE cheesetrap.reporting_schedule_versions;
ALTER TABLE cheesetrap.processing_cursors DROP COLUMN sealed_before;
