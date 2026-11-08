-- Every caller locks processing_cursors before any schedule or window row.
-- name: ReportingClock :one
SELECT greatest(clock_timestamp(),sealed_before,(SELECT next_start FROM cheesetrap.reporting_schedule_cursor WHERE singleton))::timestamptz AS now FROM cheesetrap.processing_cursors WHERE singleton;

-- name: LockReportScheduleCursor :one
SELECT next_start FROM cheesetrap.reporting_schedule_cursor WHERE singleton FOR UPDATE;

-- name: FirstReportDay :one
SELECT (date_trunc('day',coalesce(min(ingested_at),sqlc.arg(now)::timestamptz) AT TIME ZONE 'UTC') AT TIME ZONE 'UTC')::timestamptz AS start_at FROM cheesetrap.events;

-- name: SetReportScheduleCursor :exec
UPDATE cheesetrap.reporting_schedule_cursor SET next_start=$1 WHERE singleton;

-- name: ReportScheduleAt :one
SELECT * FROM cheesetrap.reporting_schedule_versions WHERE effective_from<=$1 ORDER BY effective_from DESC,version DESC LIMIT 1;

-- name: InsertReportSchedule :one
INSERT INTO cheesetrap.reporting_schedule_versions(timezone,period_days,effective_from) VALUES($1,$2,$3) RETURNING *;

-- name: GetReportWindowAt :one
SELECT * FROM cheesetrap.report_windows WHERE start_at=$1;

-- name: GetReportWindowContaining :one
SELECT * FROM cheesetrap.report_windows WHERE start_at<=$1 AND end_at>$1 ORDER BY start_at DESC LIMIT 1;

-- name: EnsureReportWindow :one
INSERT INTO cheesetrap.report_windows(start_at,end_at,settings_version) VALUES($1,$2,$3)
ON CONFLICT(start_at) DO NOTHING RETURNING *;

-- name: LockReportWindow :one
SELECT * FROM cheesetrap.report_windows WHERE window_id=$1 FOR UPDATE;

-- name: ReportSealSequence :one
SELECT coalesce(max(ingestion_seq),0)::bigint AS sealed_seq FROM cheesetrap.events WHERE ingested_at<$1;

-- name: SetReportWindowSealed :one
UPDATE cheesetrap.report_windows SET state='sealed',sealed_seq=$2,sealed_at=clock_timestamp() WHERE window_id=$1 AND state='open' RETURNING *;

-- name: SetReportWindowReady :execrows
UPDATE cheesetrap.report_windows SET state='ready',ready_at=clock_timestamp() WHERE window_id=$1 AND state='sealed' AND sealed_seq<=$2;

-- name: AdvanceSealedBefore :exec
UPDATE cheesetrap.processing_cursors SET sealed_before=greatest(sealed_before,$1) WHERE singleton;
