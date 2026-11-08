-- +goose Up
-- Prerequisite: cheesetrap_migration owns schema cheesetrap; runtime roles only
-- have CONNECT/USAGE. Bootstrap removes PUBLIC CREATE and database TEMP.
-- Collector owns the future batch transaction: processing_cursors row lock ->
-- event inserts -> checkpoints -> ingested_seq, then COMMIT. A PostgreSQL
-- sequence cannot represent commit order; ingestion_seq has NO sequence/default.
-- Worker owns detection transactions and takes the same cursor lock first.
-- No filesystem, SMTP, HTTP, DNS, or other external I/O inside either transaction.
ALTER DEFAULT PRIVILEGES IN SCHEMA cheesetrap REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA cheesetrap REVOKE ALL ON SEQUENCES FROM PUBLIC;
-- PUBLIC EXECUTE is a global default, so a per-schema revoke cannot remove it.
ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

CREATE TABLE cheesetrap.sensors (
    sensor_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name text NOT NULL UNIQUE CHECK (length(name) > 0),
    engine text NOT NULL CHECK (length(engine) > 0),
    engine_version text,
    config_version bigint NOT NULL DEFAULT 1 CHECK (config_version > 0),
    public_ip inet,
    public_port integer CHECK (public_port BETWEEN 1 AND 65535),
    state text NOT NULL DEFAULT 'unknown' CHECK (state IN ('unknown','active','degraded','disabled')),
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK (public_ip IS NULL OR masklen(public_ip) = CASE family(public_ip) WHEN 4 THEN 32 ELSE 128 END)
);

-- Device/inode are observations, not globally unique identity: inode reuse and
-- truncation produce a NEW generation UUID even when these values match.
CREATE TABLE cheesetrap.file_generations (
    file_generation_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    sensor_id uuid NOT NULL REFERENCES cheesetrap.sensors(sensor_id),
    path text NOT NULL CHECK (length(path) > 0),
    device numeric(20,0) NOT NULL CHECK (device >= 0),
    inode numeric(20,0) NOT NULL CHECK (inode >= 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    closed_at timestamptz,
    UNIQUE (sensor_id, file_generation_id),
    CHECK (closed_at IS NULL OR closed_at >= created_at)
);
CREATE INDEX file_generations_identity_idx ON cheesetrap.file_generations(sensor_id, device, inode, created_at DESC);
CREATE INDEX file_generations_open_idx ON cheesetrap.file_generations(sensor_id, path) WHERE closed_at IS NULL;

CREATE TABLE cheesetrap.checkpoints (
    sensor_id uuid NOT NULL,
    file_generation_id uuid NOT NULL,
    byte_offset bigint NOT NULL DEFAULT 0 CHECK (byte_offset >= 0),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (sensor_id, file_generation_id),
    FOREIGN KEY (sensor_id, file_generation_id) REFERENCES cheesetrap.file_generations(sensor_id, file_generation_id)
);

CREATE TABLE cheesetrap.events (
    event_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    sensor_id uuid NOT NULL,
    file_generation_id uuid NOT NULL,
    byte_offset bigint NOT NULL CHECK (byte_offset >= 0),
    ingestion_seq bigint NOT NULL UNIQUE CHECK (ingestion_seq > 0),
    schema_version integer NOT NULL CHECK (schema_version > 0),
    engine text NOT NULL CHECK (length(engine) > 0),
    observed_at timestamptz,
    ingested_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    source_ip inet,
    source_port integer CHECK (source_port BETWEEN 0 AND 65535),
    destination_ip inet,
    destination_port integer CHECK (destination_port BETWEEN 0 AND 65535),
    service text NOT NULL CHECK (length(service) > 0),
    event_type text NOT NULL CHECK (length(event_type) > 0),
    session_id text,
    attributes jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(attributes) = 'object'),
    raw_hash text NOT NULL CHECK (raw_hash ~ '^[a-f0-9]{64}$'),
    quality_flags text[] NOT NULL DEFAULT '{}',
    is_test boolean NOT NULL DEFAULT false,
    UNIQUE (sensor_id, file_generation_id, byte_offset),
    FOREIGN KEY (sensor_id, file_generation_id) REFERENCES cheesetrap.file_generations(sensor_id, file_generation_id),
    CHECK (source_ip IS NULL OR masklen(source_ip) = CASE family(source_ip) WHEN 4 THEN 32 ELSE 128 END),
    CHECK (destination_ip IS NULL OR masklen(destination_ip) = CASE family(destination_ip) WHEN 4 THEN 32 ELSE 128 END)
);
COMMENT ON COLUMN cheesetrap.events.source_ip IS 'Directly observed peer address, never an attacker-supplied forwarding header; null when unavailable.';
COMMENT ON COLUMN cheesetrap.events.attributes IS 'Normalized, redacted evidence only; never raw passwords, cookies, tokens, or engine payloads.';
CREATE INDEX events_source_time_idx ON cheesetrap.events(source_ip, ingested_at, ingestion_seq);
CREATE INDEX events_service_time_idx ON cheesetrap.events(service, ingested_at, ingestion_seq);
CREATE INDEX events_ingested_time_idx ON cheesetrap.events(ingested_at, ingestion_seq);
CREATE INDEX events_sensor_observed_idx ON cheesetrap.events(sensor_id, observed_at);

CREATE TABLE cheesetrap.processing_cursors (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    ingested_seq bigint NOT NULL DEFAULT 0 CHECK (ingested_seq >= 0),
    detected_seq bigint NOT NULL DEFAULT 0 CHECK (detected_seq >= 0 AND detected_seq <= ingested_seq)
);
INSERT INTO cheesetrap.processing_cursors(singleton) VALUES (true);

GRANT SELECT ON cheesetrap.sensors, cheesetrap.events, cheesetrap.processing_cursors TO cheesetrap_api, cheesetrap_collector, cheesetrap_worker;
GRANT INSERT, UPDATE ON cheesetrap.sensors TO cheesetrap_collector;
GRANT SELECT, INSERT, UPDATE ON cheesetrap.file_generations, cheesetrap.checkpoints TO cheesetrap_collector;
GRANT INSERT ON cheesetrap.events TO cheesetrap_collector;
GRANT UPDATE (ingested_seq) ON cheesetrap.processing_cursors TO cheesetrap_collector;
GRANT UPDATE (detected_seq) ON cheesetrap.processing_cursors TO cheesetrap_worker;

-- +goose Down
DROP TABLE cheesetrap.processing_cursors;
DROP TABLE cheesetrap.events;
DROP TABLE cheesetrap.checkpoints;
DROP TABLE cheesetrap.file_generations;
DROP TABLE cheesetrap.sensors;
