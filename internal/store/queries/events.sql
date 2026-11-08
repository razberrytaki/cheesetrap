-- Caller owns transactions. Collector lock order: cursor -> events -> checkpoint
-- -> ingestion cursor update. Keep the lock through COMMIT; allocate consecutive
-- ingestion_seq values under this lock, never using a database sequence.
-- Worker locks the cursor before detection work and detected_seq update.
-- Do not perform filesystem/SMTP/HTTP/DNS or any external I/O in transactions.

-- name: LockProcessingCursors :one
SELECT ingested_seq, detected_seq FROM cheesetrap.processing_cursors WHERE singleton FOR UPDATE;

-- name: GetProcessingCursors :one
SELECT ingested_seq, detected_seq FROM cheesetrap.processing_cursors WHERE singleton;

-- name: AdvanceIngestedCursor :execrows
UPDATE cheesetrap.processing_cursors SET ingested_seq = $1 WHERE singleton AND ingested_seq <= $1;

-- name: AdvanceDetectedCursor :execrows
UPDATE cheesetrap.processing_cursors SET detected_seq = $1 WHERE singleton AND detected_seq <= $1;

-- name: CreateSensor :one
INSERT INTO cheesetrap.sensors(sensor_id, name, engine) VALUES ($1, $2, $3) RETURNING *;

-- name: GetSensor :one
SELECT * FROM cheesetrap.sensors WHERE sensor_id = $1;

-- name: CreateFileGeneration :one
INSERT INTO cheesetrap.file_generations(file_generation_id, sensor_id, path, device, inode) VALUES ($1, $2, $3, $4, $5) RETURNING *;

-- name: FindFileGenerations :many
SELECT * FROM cheesetrap.file_generations WHERE sensor_id = $1 AND device = $2 AND inode = $3 ORDER BY created_at DESC;

-- name: CloseFileGeneration :exec
UPDATE cheesetrap.file_generations SET closed_at = clock_timestamp() WHERE file_generation_id = $1 AND closed_at IS NULL;

-- name: GetCheckpoint :one
SELECT * FROM cheesetrap.checkpoints WHERE sensor_id = $1 AND file_generation_id = $2;

-- name: SetCheckpoint :exec
INSERT INTO cheesetrap.checkpoints(sensor_id, file_generation_id, byte_offset) VALUES ($1, $2, $3)
ON CONFLICT(sensor_id, file_generation_id) DO UPDATE SET byte_offset = EXCLUDED.byte_offset, updated_at = clock_timestamp() WHERE checkpoints.byte_offset <= EXCLUDED.byte_offset;

-- name: InsertEvent :one
INSERT INTO cheesetrap.events(sensor_id,file_generation_id,byte_offset,ingestion_seq,schema_version,engine,observed_at,ingested_at,source_ip,source_port,destination_ip,destination_port,service,event_type,session_id,attributes,raw_hash,quality_flags,is_test,byte_end_offset)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)
ON CONFLICT(sensor_id,file_generation_id,byte_offset) DO NOTHING RETURNING event_id, ingestion_seq, ingested_at;

-- name: GetEventByIngestionKey :one
SELECT * FROM cheesetrap.events WHERE sensor_id = $1 AND file_generation_id = $2 AND byte_offset = $3;

-- name: ListEventsAfterSequence :many
SELECT * FROM cheesetrap.events WHERE ingestion_seq > $1 ORDER BY ingestion_seq LIMIT $2;

-- name: CommitClock :one
SELECT greatest(clock_timestamp(),sealed_before)::timestamptz AS collected_at FROM cheesetrap.processing_cursors WHERE singleton;

-- name: EnsureCollectorSensor :one
-- A supplied pre-Poll lower bound initializes only a new sensor. Existing
-- identities retain their bound until the batch's atomic state update.
INSERT INTO cheesetrap.sensors(sensor_id,name,engine,last_observation_at)
VALUES ($1,$2,$3,coalesce(sqlc.narg(initial_observation)::timestamptz,clock_timestamp()))
ON CONFLICT(sensor_id) DO UPDATE SET name=EXCLUDED.name
WHERE sensors.name=EXCLUDED.name AND sensors.engine=EXCLUDED.engine RETURNING *;

-- name: SaveGenerationWitness :one
INSERT INTO cheesetrap.file_generations(file_generation_id,sensor_id,path,device,inode,created_at,observed_size,fingerprint_bytes,fingerprint_sha256)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
ON CONFLICT(file_generation_id) DO UPDATE SET
 path=EXCLUDED.path, observed_size=greatest(file_generations.observed_size,EXCLUDED.observed_size),
 fingerprint_bytes=greatest(file_generations.fingerprint_bytes,EXCLUDED.fingerprint_bytes),
 fingerprint_sha256=CASE WHEN EXCLUDED.fingerprint_bytes > file_generations.fingerprint_bytes THEN EXCLUDED.fingerprint_sha256 ELSE file_generations.fingerprint_sha256 END
WHERE file_generations.sensor_id=EXCLUDED.sensor_id AND file_generations.device=EXCLUDED.device AND file_generations.inode=EXCLUDED.inode
 AND file_generations.created_at=EXCLUDED.created_at
 AND (file_generations.fingerprint_bytes<>EXCLUDED.fingerprint_bytes OR file_generations.fingerprint_sha256=EXCLUDED.fingerprint_sha256)
RETURNING *;

-- name: ListCollectorResume :many
SELECT g.*, coalesce(c.byte_offset,0)::bigint AS byte_offset
FROM cheesetrap.file_generations g LEFT JOIN cheesetrap.checkpoints c USING(sensor_id,file_generation_id)
WHERE g.sensor_id=$1 AND g.closed_at IS NULL ORDER BY g.created_at,g.file_generation_id LIMIT 65;

-- name: FindCommittedEvidence :many
SELECT raw_hash, byte_end_offset, 'event'::text AS kind FROM cheesetrap.events e WHERE e.sensor_id=$1 AND e.file_generation_id=$2 AND e.byte_offset=$3
UNION ALL
SELECT raw_hash, byte_end_offset, 'rejection'::text AS kind FROM cheesetrap.ingestion_rejections r WHERE r.sensor_id=$1 AND r.file_generation_id=$2 AND r.byte_offset=$3;

-- name: InsertRejection :exec
INSERT INTO cheesetrap.ingestion_rejections(sensor_id,file_generation_id,byte_offset,byte_end_offset,byte_count,raw_hash,reason)
VALUES($1,$2,$3,$4,$5,$6,$7);

-- name: MarkCollectionGap :exec
INSERT INTO cheesetrap.ingestion_gaps(sensor_id,started_at,observed_through) VALUES ($1,least($2::timestamptz,clock_timestamp()),clock_timestamp())
ON CONFLICT(sensor_id) DO UPDATE SET started_at=least(ingestion_gaps.started_at,EXCLUDED.started_at),observed_through=greatest(ingestion_gaps.observed_through,EXCLUDED.observed_through);

-- name: UpdateCollectorState :exec
UPDATE cheesetrap.sensors SET last_observation_at=greatest(last_observation_at,$2::timestamptz), state=CASE WHEN EXISTS(SELECT 1 FROM cheesetrap.ingestion_gaps g WHERE g.sensor_id=$1) THEN 'degraded' ELSE 'active' END WHERE sensors.sensor_id=$1;

-- name: CloseSensorGeneration :exec
UPDATE cheesetrap.file_generations SET closed_at=greatest(clock_timestamp(),created_at) WHERE sensor_id=$1 AND file_generation_id=$2 AND closed_at IS NULL;

-- name: GetCollectionGap :one
SELECT * FROM cheesetrap.ingestion_gaps WHERE sensor_id=$1;

-- name: ListAPIEvents :many
-- Immutable ingestion sequence is a unique stable descending cursor. Project
-- only normalized evidence, capping each attributes object before transport.
SELECT event_id,ingestion_seq,engine,observed_at,ingested_at,source_ip,source_port,
 destination_ip,destination_port,service,event_type,session_id,quality_flags,is_test,
 CASE WHEN octet_length(attributes::text)<=16384 THEN attributes ELSE '{}'::jsonb END AS attributes,
 octet_length(attributes::text)>16384 AS attributes_truncated,
 (CASE WHEN ingestion_seq>sqlc.arg(detected_snapshot)::bigint THEN 'pending'
 ELSE cheesetrap.event_detection_result(event_id,ingestion_seq,sqlc.arg(detected_snapshot)::bigint) END)::text AS detection_result
FROM cheesetrap.events
WHERE ingestion_seq<=sqlc.arg(snapshot)::bigint AND (sqlc.narg(before_seq)::bigint IS NULL OR ingestion_seq<sqlc.narg(before_seq))
 AND (sqlc.narg(source_ip)::inet IS NULL OR source_ip=sqlc.narg(source_ip))
 AND (sqlc.narg(service)::text IS NULL OR service=sqlc.narg(service))
 AND (sqlc.narg(event_type)::text IS NULL OR event_type=sqlc.narg(event_type))
 AND (sqlc.narg(since)::timestamptz IS NULL OR ingested_at>=sqlc.narg(since))
 AND (sqlc.narg(until)::timestamptz IS NULL OR ingested_at<sqlc.narg(until))
 AND (sqlc.narg(is_test)::boolean IS NULL OR is_test=sqlc.narg(is_test))
 AND (sqlc.narg(detection_result)::text IS NULL OR cheesetrap.event_detection_result(event_id,ingestion_seq,sqlc.arg(detected_snapshot)::bigint)=sqlc.narg(detection_result))
ORDER BY ingestion_seq DESC LIMIT sqlc.arg(page_limit);

-- name: ListAPIPendingEvents :many
-- A dedicated branch keeps the processing lower bound indexable even with a
-- generic prepared plan. Pending events never need membership/history lookup.
SELECT event_id,ingestion_seq,engine,observed_at,ingested_at,source_ip,source_port,
 destination_ip,destination_port,service,event_type,session_id,quality_flags,is_test,
 CASE WHEN octet_length(attributes::text)<=16384 THEN attributes ELSE '{}'::jsonb END AS attributes,
 octet_length(attributes::text)>16384 AS attributes_truncated,
 'pending'::text AS detection_result
FROM cheesetrap.events
WHERE ingestion_seq>sqlc.arg(detected_snapshot)::bigint AND ingestion_seq<=sqlc.arg(snapshot)::bigint AND (sqlc.narg(before_seq)::bigint IS NULL OR ingestion_seq<sqlc.narg(before_seq))
 AND (sqlc.narg(source_ip)::inet IS NULL OR source_ip=sqlc.narg(source_ip))
 AND (sqlc.narg(service)::text IS NULL OR service=sqlc.narg(service))
 AND (sqlc.narg(event_type)::text IS NULL OR event_type=sqlc.narg(event_type))
 AND (sqlc.narg(since)::timestamptz IS NULL OR ingested_at>=sqlc.narg(since))
 AND (sqlc.narg(until)::timestamptz IS NULL OR ingested_at<sqlc.narg(until))
 AND (sqlc.narg(is_test)::boolean IS NULL OR is_test=sqlc.narg(is_test))
ORDER BY ingestion_seq DESC LIMIT sqlc.arg(page_limit);

-- name: GetAPIEvent :one
SELECT event_id,ingestion_seq,engine,observed_at,ingested_at,source_ip,source_port,
 destination_ip,destination_port,service,event_type,session_id,quality_flags,is_test,
 CASE WHEN octet_length(attributes::text)<=16384 THEN attributes ELSE '{}'::jsonb END AS attributes,
 octet_length(attributes::text)>16384 AS attributes_truncated,
 cheesetrap.event_detection_result(event_id,ingestion_seq,(SELECT detected_seq FROM cheesetrap.processing_cursors WHERE singleton))::text AS detection_result
FROM cheesetrap.events WHERE event_id=$1;

-- name: GetAPIOverview :one
SELECT ingested_seq,detected_seq,
 (SELECT count(*) FROM cheesetrap.sensors WHERE state='active') AS sensors_active,
 (SELECT count(*) FROM cheesetrap.sensors WHERE state='degraded') AS sensors_degraded,
 (SELECT count(*) FROM cheesetrap.sensors WHERE state='unknown') AS sensors_unknown,
 (SELECT count(*) FROM cheesetrap.sensors WHERE state='disabled') AS sensors_disabled,
 (SELECT count(*) FROM cheesetrap.ingestion_gaps) AS sensors_with_gaps
FROM cheesetrap.processing_cursors WHERE singleton;

-- name: CheckAPIReady :one
SELECT EXISTS(SELECT 1 FROM cheesetrap.processing_cursors WHERE singleton)
 AND (SELECT count(*)>=0 FROM cheesetrap.admins)
 AND NOT EXISTS(SELECT 1 FROM cheesetrap.sessions WHERE false)
 AND NOT EXISTS(SELECT 1 FROM cheesetrap.events WHERE false) AS ready;
