-- +goose Up
-- DB-clock lower bound captured before file polling, not a commit timestamp.
ALTER TABLE cheesetrap.sensors ADD COLUMN last_observation_at timestamptz NOT NULL DEFAULT clock_timestamp();
ALTER TABLE cheesetrap.file_generations
 ADD COLUMN observed_size bigint NOT NULL DEFAULT 0 CHECK (observed_size >= 0),
 ADD COLUMN fingerprint_bytes integer NOT NULL DEFAULT 0 CHECK (fingerprint_bytes BETWEEN 0 AND 4096),
 ADD COLUMN fingerprint_sha256 text NOT NULL DEFAULT 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' CHECK (fingerprint_sha256 ~ '^[a-f0-9]{64}$'),
 ADD CHECK (observed_size >= fingerprint_bytes);
ALTER TABLE cheesetrap.events ADD COLUMN byte_end_offset bigint CHECK (byte_end_offset > byte_offset);
CREATE TABLE cheesetrap.ingestion_rejections (
 sensor_id uuid NOT NULL,
 file_generation_id uuid NOT NULL,
 byte_offset bigint NOT NULL CHECK (byte_offset >= 0),
 byte_end_offset bigint NOT NULL CHECK (byte_end_offset > byte_offset),
 byte_count bigint NOT NULL CHECK (byte_count = byte_end_offset - byte_offset - 1),
 raw_hash text NOT NULL CHECK (raw_hash ~ '^[a-f0-9]{64}$'),
 reason text NOT NULL CHECK (reason IN ('invalid_json','record_too_large','adapter_rejected')),
 recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(sensor_id,file_generation_id,byte_offset),
 FOREIGN KEY(sensor_id,file_generation_id) REFERENCES cheesetrap.file_generations(sensor_id,file_generation_id)
);
-- Conservative unresolved gap interval. It remains degraded across restart;
-- clearing/resolving a gap requires a future explicit operator workflow.
CREATE TABLE cheesetrap.ingestion_gaps (
 sensor_id uuid PRIMARY KEY REFERENCES cheesetrap.sensors(sensor_id),
 started_at timestamptz NOT NULL,
 observed_through timestamptz NOT NULL CHECK (observed_through >= started_at)
);
GRANT SELECT ON cheesetrap.ingestion_rejections,cheesetrap.ingestion_gaps TO cheesetrap_api,cheesetrap_collector,cheesetrap_worker;
GRANT INSERT ON cheesetrap.ingestion_rejections TO cheesetrap_collector;
GRANT INSERT,UPDATE ON cheesetrap.ingestion_gaps TO cheesetrap_collector;

-- +goose Down
ALTER TABLE cheesetrap.sensors DROP COLUMN last_observation_at;
DROP TABLE cheesetrap.ingestion_gaps;
DROP TABLE cheesetrap.ingestion_rejections;
ALTER TABLE cheesetrap.events DROP COLUMN byte_end_offset;
ALTER TABLE cheesetrap.file_generations DROP COLUMN fingerprint_sha256, DROP COLUMN fingerprint_bytes, DROP COLUMN observed_size;
