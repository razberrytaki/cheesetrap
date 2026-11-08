-- +goose Up
-- Keep payloads that cannot affect processing out of worker result sets. The
-- source event remains unchanged and available through the evidence API.
CREATE VIEW cheesetrap.processing_events AS
SELECT event_id,sensor_id,file_generation_id,byte_offset,ingestion_seq,schema_version,
 engine,observed_at,ingested_at,source_ip,source_port,destination_ip,destination_port,
 service,event_type,session_id,
 jsonb_build_object('method',attributes->'method','uri',attributes->'uri',
 'command',attributes->'command','field_completeness',attributes->'field_completeness',
 'truncation',attributes->'truncation','parse_error',attributes->'parse_error') AS attributes,
 raw_hash,quality_flags,is_test,byte_end_offset FROM cheesetrap.events;
GRANT SELECT ON cheesetrap.processing_events TO cheesetrap_worker;

-- The processing-cursor lock gives this staging relation a single writer.
-- Entries are removed before the event transaction commits; rollback and crash
-- recovery leave neither a partial result nor an advanced cursor.
CREATE TABLE cheesetrap.detection_work (
 rule_id text NOT NULL,event_id uuid NOT NULL,ingestion_seq bigint NOT NULL,
 observed_at timestamptz NOT NULL,path text NOT NULL,holds text[] NOT NULL,
 PRIMARY KEY(rule_id,event_id)
);
CREATE INDEX detection_work_window ON cheesetrap.detection_work(rule_id,observed_at);
CREATE INDEX detection_work_sequence ON cheesetrap.detection_work(rule_id,ingestion_seq);
GRANT SELECT,INSERT,DELETE ON cheesetrap.detection_work TO cheesetrap_worker;

ALTER TABLE cheesetrap.detection_results ADD COLUMN evidence_hash_scheme text NOT NULL
 DEFAULT 'sha256-json-v1' CHECK(evidence_hash_scheme IN ('sha256-json-v1','sha256-chain-v2'));
ALTER TABLE cheesetrap.detection_results ADD CONSTRAINT evidence_hash_representation
 CHECK(evidence_hash_scheme='sha256-json-v1' OR evidence_representation='chunks-v1');

-- v2 hashes UUIDs in ascending byte order with a constant-size state. Unlike
-- array_agg, the ORDER BY sort can spill to disk under PostgreSQL work_mem.
CREATE TYPE cheesetrap.evidence_hash_state AS (digest bytea,n bigint);
-- +goose StatementBegin
CREATE FUNCTION cheesetrap.evidence_chain_step(s cheesetrap.evidence_hash_state,id uuid)
RETURNS cheesetrap.evidence_hash_state LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,cheesetrap AS $$
 SELECT ROW(sha256(coalesce(s.digest,sha256(convert_to('cheesetrap:evidence:sha256-chain-v2','UTF8')))||uuid_send(id)),coalesce(s.n,0)+1)::cheesetrap.evidence_hash_state
$$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE FUNCTION cheesetrap.evidence_chain_final(s cheesetrap.evidence_hash_state)
RETURNS text LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,cheesetrap AS $$
 SELECT encode(sha256(coalesce(s.digest,sha256(convert_to('cheesetrap:evidence:sha256-chain-v2','UTF8')))||int8send(coalesce(s.n,0))),'hex')
$$;
-- +goose StatementEnd
CREATE AGGREGATE cheesetrap.evidence_chain_hash(uuid) (
 SFUNC=cheesetrap.evidence_chain_step,STYPE=cheesetrap.evidence_hash_state,FINALFUNC=cheesetrap.evidence_chain_final
);

-- One bucket per call. Exact membership, retry identity and collision checks
-- are bounded by the maximum bucket width, including inside the database.
-- +goose StatementBegin
CREATE FUNCTION cheesetrap.prepare_detection_bucket(root_id uuid,bucket bigint,event_ids uuid[])
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,cheesetrap SET jit=off AS $$
DECLARE r cheesetrap.detection_results; ids uuid[]; stored uuid[]; cid uuid; digest text;
BEGIN
 PERFORM 1 FROM cheesetrap.processing_cursors WHERE singleton FOR UPDATE;
 SELECT * INTO r FROM cheesetrap.detection_results WHERE detection_id=root_id FOR UPDATE;
 IF NOT FOUND OR r.evidence_state<>'active' OR r.evidence_representation<>'chunks-v1' OR r.evidence_hash_scheme<>'sha256-chain-v2' THEN RAISE EXCEPTION 'invalid_streamed_root' USING ERRCODE='23514'; END IF;
 IF event_ids IS NULL OR cardinality(event_ids) NOT BETWEEN 1 AND 128 OR array_position(event_ids,NULL) IS NOT NULL THEN RAISE EXCEPTION 'invalid_bucket_members' USING ERRCODE='23514'; END IF;
 SELECT array_agg(DISTINCT id ORDER BY id) INTO ids FROM unnest(event_ids) id;
 IF cardinality(ids)<>cardinality(event_ids) OR EXISTS(SELECT 1 FROM unnest(ids) id WHERE NOT EXISTS(SELECT 1 FROM cheesetrap.events e WHERE e.event_id=id AND (e.ingestion_seq-1)/128=bucket)) THEN RAISE EXCEPTION 'invalid_bucket_members' USING ERRCODE='23514'; END IF;
 digest:=cheesetrap.chunk_content_hash(128,bucket,ids);
 SELECT chunk_id INTO cid FROM cheesetrap.evidence_chunks WHERE encoding_version=1 AND bucket_width=128 AND bucket_no=bucket AND content_hash=digest AND NOT retired;
 IF FOUND THEN
  SELECT array_agg(event_id ORDER BY event_id) INTO stored FROM cheesetrap.evidence_chunk_members WHERE chunk_id=cid;
  IF stored IS DISTINCT FROM ids THEN RAISE EXCEPTION 'chunk_content_collision' USING ERRCODE='23514'; END IF;
 ELSE
  INSERT INTO cheesetrap.evidence_chunks(bucket_width,bucket_no,content_hash,member_count) VALUES(128,bucket,digest,cardinality(ids)) RETURNING chunk_id INTO cid;
  INSERT INTO cheesetrap.evidence_chunk_members SELECT cid,unnest(ids);
 END IF;
 RETURN cid;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION cheesetrap.prepare_detection_bucket(uuid,bigint,uuid[]) FROM PUBLIC;

-- One sorted pass over the staged context; each array has at most 128 members.
-- A single reference INSERT retains the immediate attachment guard without
-- rechecking an ever-growing prefix for every bucket. GroupAggregate spills
-- its input sort rather than accumulating every bucket in a hash aggregate.
-- +goose StatementBegin
CREATE FUNCTION cheesetrap.attach_detection_work(root_id uuid,rule text,start_at timestamptz,end_at timestamptz)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,cheesetrap SET jit=off SET work_mem='4MB' SET enable_hashagg=off AS $$
BEGIN
 PERFORM 1 FROM cheesetrap.processing_cursors WHERE singleton FOR UPDATE;
 INSERT INTO cheesetrap.detection_evidence_chunks
 SELECT root_id,bucket,cheesetrap.prepare_detection_bucket(root_id,bucket,ids)
 FROM (SELECT (ingestion_seq-1)/128 AS bucket,array_agg(event_id ORDER BY event_id) AS ids
       FROM cheesetrap.detection_work WHERE rule_id=rule AND observed_at BETWEEN start_at AND end_at
       GROUP BY (ingestion_seq-1)/128) parts;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION cheesetrap.attach_detection_work(uuid,text,timestamptz,timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION cheesetrap.attach_detection_work(uuid,text,timestamptz,timestamptz) TO cheesetrap_worker;

-- Old proofs retain their exact v1 identity. Only new v2 roots use the bounded
-- aggregate; the deferred check still proves complete, duplicate-free membership.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION cheesetrap.validate_evidence_root() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,cheesetrap SET jit=off SET work_mem='4MB' AS $$
DECLARE r cheesetrap.detection_results; n bigint; unique_n bigint; widths bigint; ids uuid[]; digest text;
BEGIN
 SELECT * INTO r FROM cheesetrap.detection_results WHERE detection_id=NEW.detection_id;
 IF NOT FOUND OR r.evidence_state='retiring' THEN RETURN NULL; END IF;
 IF r.evidence_representation='chunks-v1' THEN
  IF r.evidence_hash_scheme='sha256-chain-v2' THEN
   SELECT count(*),count(DISTINCT m.event_id),count(DISTINCT c.bucket_width),cheesetrap.evidence_chain_hash(m.event_id ORDER BY m.event_id) INTO n,unique_n,widths,digest
   FROM cheesetrap.detection_evidence_chunks d
   CROSS JOIN LATERAL (SELECT bucket_width FROM cheesetrap.evidence_chunks WHERE chunk_id=d.chunk_id OFFSET 0) c
   CROSS JOIN LATERAL (SELECT event_id FROM cheesetrap.evidence_chunk_members WHERE chunk_id=d.chunk_id OFFSET 0) m WHERE d.detection_id=r.detection_id;
  ELSE
   SELECT count(*),count(DISTINCT m.event_id),count(DISTINCT c.bucket_width),array_agg(m.event_id ORDER BY m.event_id) INTO n,unique_n,widths,ids
   FROM cheesetrap.detection_evidence_chunks d
   CROSS JOIN LATERAL (SELECT bucket_width FROM cheesetrap.evidence_chunks WHERE chunk_id=d.chunk_id OFFSET 0) c
   CROSS JOIN LATERAL (SELECT event_id FROM cheesetrap.evidence_chunk_members WHERE chunk_id=d.chunk_id OFFSET 0) m WHERE d.detection_id=r.detection_id;
   digest:=cheesetrap.evidence_set_hash(ids);
  END IF;
  IF n<>r.evidence_count OR n<>unique_n OR widths<>1 OR r.evidence_hash IS DISTINCT FROM digest OR EXISTS(SELECT 1 FROM cheesetrap.detection_evidence WHERE detection_id=r.detection_id) THEN RAISE EXCEPTION 'incomplete_evidence_root' USING ERRCODE='23514'; END IF;
 END IF;
 RETURN NULL;
END $$;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN RAISE EXCEPTION 'streamed_evidence_downgrade_requires_data_preservation'; END $$;
-- +goose StatementEnd
