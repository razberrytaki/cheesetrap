-- +goose Up
-- Evidence, results, and completions are immutable to runtime roles. Attribution
-- is the processing event's ingestion sequence, even for late observed evidence.
ALTER TABLE cheesetrap.events ADD CONSTRAINT events_id_sequence_unique UNIQUE(event_id,ingestion_seq);
CREATE INDEX events_source_observed_idx ON cheesetrap.events(source_ip,observed_at,ingestion_seq);
CREATE TABLE cheesetrap.detection_completions (
 ingestion_seq bigint PRIMARY KEY,
 event_id uuid NOT NULL UNIQUE,
 rule_set_version text NOT NULL CHECK(length(rule_set_version)>0),
 completed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(event_id,ingestion_seq),
 FOREIGN KEY(event_id,ingestion_seq) REFERENCES cheesetrap.events(event_id,ingestion_seq)
);
CREATE TABLE cheesetrap.detection_results (
 detection_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 rule_id text NOT NULL CHECK(rule_id IN ('SSH-REPEAT','WEB-REPEAT','WEB-EXPLOIT')),
 rule_version text NOT NULL CHECK(length(rule_version)>0),
 signature_id text NOT NULL DEFAULT '',
 signature_version text NOT NULL DEFAULT '',
 processing_event_id uuid NOT NULL,
 processing_ingestion_seq bigint NOT NULL,
 source_ip inet NOT NULL,
 window_start timestamptz NOT NULL,
 window_end timestamptz NOT NULL CHECK(window_end>=window_start),
 evidence_hash text NOT NULL CHECK(evidence_hash ~ '^[a-f0-9]{64}$'),
 evidence_count integer NOT NULL CHECK(evidence_count>0),
 evidence_eligible boolean NOT NULL,
 auto_approval_allowed boolean NOT NULL,
 explanation jsonb NOT NULL CHECK(jsonb_typeof(explanation)='object'),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 CHECK(masklen(source_ip)=CASE family(source_ip) WHEN 4 THEN 32 ELSE 128 END),
 CHECK((rule_id='WEB-EXPLOIT' AND length(signature_id)>0 AND length(signature_version)>0) OR (rule_id<>'WEB-EXPLOIT' AND signature_id='' AND signature_version='')),
 UNIQUE(rule_id,rule_version,signature_id,signature_version,processing_event_id,evidence_hash),
 FOREIGN KEY(processing_event_id,processing_ingestion_seq) REFERENCES cheesetrap.detection_completions(event_id,ingestion_seq) DEFERRABLE INITIALLY DEFERRED
);
CREATE INDEX detection_results_processing_idx ON cheesetrap.detection_results(processing_ingestion_seq,detection_id);
CREATE TABLE cheesetrap.detection_evidence (
 detection_id uuid NOT NULL REFERENCES cheesetrap.detection_results(detection_id),
 event_id uuid NOT NULL REFERENCES cheesetrap.events(event_id),
 PRIMARY KEY(detection_id,event_id)
);
CREATE INDEX detection_evidence_event_idx ON cheesetrap.detection_evidence(event_id);
COMMENT ON COLUMN cheesetrap.detection_results.evidence_eligible IS 'Evidence-level eligibility only. Registry, approval, report, and delivery gates are still required.';
GRANT SELECT ON cheesetrap.detection_completions,cheesetrap.detection_results,cheesetrap.detection_evidence TO cheesetrap_api,cheesetrap_worker;
GRANT INSERT ON cheesetrap.detection_completions,cheesetrap.detection_results,cheesetrap.detection_evidence TO cheesetrap_worker;

-- +goose Down
DROP TABLE cheesetrap.detection_evidence;
DROP TABLE cheesetrap.detection_results;
DROP TABLE cheesetrap.detection_completions;
DROP INDEX cheesetrap.events_source_observed_idx;
ALTER TABLE cheesetrap.events DROP CONSTRAINT events_id_sequence_unique;
